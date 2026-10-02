# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
"""Inspect nft list-ruleset JSON; never execute or predict firewall packet flow."""
import ipaddress
from .common import InputError, Report, mapping, sequence, string

LIMITS=['Structural ingress policy review, not packet simulation or proof of isolation. Hook priorities, jumps, sets/maps, NAT, other namespaces, offload and preceding controls need host review.',
 'Only list-ruleset JSON objects are accepted, never command objects. Missing protection for either IPv4/IPv6 ingress is OPEN.',
 'Match conditions are treated conservatively: complex unsupported expressions cannot establish narrow exposure.']

MATCH_KEYS={'payload','meta','ct'}

def restricted(expr):
    """Recognize only simple scalar equality matches with validated selectors."""
    obj=mapping(expr,'match');left=mapping(obj.get('left'),'match.left');right=obj.get('right')
    if set(obj) != {'op','left','right'} or obj.get('op') != '==':return None
    if len(left)!=1 or not set(left).issubset(MATCH_KEYS):return None
    kind,next_=next(iter(left.items()));next_=mapping(next_,'match selector')
    if kind=='meta' and set(next_)=={'key'} and next_.get('key') in ('iifname','iif'):
        if next_['key']=='iif':return 'interface' if type(right) is int and right>0 else None
        return 'interface' if isinstance(right,str) and right and not any(c in right for c in '*?[') else None
    if kind=='payload' and set(next_)=={'protocol','field'} and next_.get('protocol') in ('ip','ip6') and next_.get('field')=='saddr':
        if isinstance(right,str):
            try: network=ipaddress.ip_network(right,strict=False)
            except ValueError:return None
            expected=4 if next_['protocol']=='ip' else 6
            return 'source' if network.version==expected and network.prefixlen>0 else None
        if isinstance(right,dict) and set(right)=={'prefix'}:
            prefix=mapping(right['prefix'],'source prefix')
            if set(prefix)!={'addr','len'}:return None
            address=prefix.get('addr');length=prefix.get('len')
            if isinstance(address,str) and type(length) is int:
                try:network=ipaddress.ip_network(address+'/'+str(length),strict=False)
                except ValueError:return None
                return 'source' if network.prefixlen>0 and network.version==(4 if next_['protocol']=='ip' else 6) else None
        return None
    if kind=='payload' and set(next_)=={'protocol','field'} and next_.get('protocol') in ('tcp','udp') and next_.get('field')=='dport':
        return 'port' if type(right) is int and 1<=right<=65535 else None
    if kind=='ct' and set(next_)=={'key'} and next_.get('key')=='state':
        if isinstance(right,str) and right in ('established','related'):return 'state'
        if isinstance(right,dict) and set(right)=={'set'} and isinstance(right['set'],list) and right['set'] and all(x in ('established','related') for x in right['set']):return 'state'
    return None

def analyze(snapshot):
    mapping(snapshot,'snapshot');objects=sequence(snapshot.get('nftables'),'nftables')
    report=Report('NftIngressAudit','All supplied nft list-ruleset ingress/forward chain policies and accept/rule structures')
    tables={};chains={};rules=[]
    for index,wrapper in enumerate(objects):
        mapping(wrapper,'nft object')
        if len(wrapper)!=1:raise InputError('nft object needs one type')
        kind,obj=next(iter(wrapper.items()));mapping(obj,'nft '+kind);where='object:'+str(index)
        if kind=='metainfo':
            version=obj.get('json_schema_version')
            if type(version) is not int or version!=1:report.add('schema','OPEN',where,'Unknown nft JSON schema version')
            continue
        if kind in ('add','delete','replace','create','insert','flush','rename','reset','list'):raise InputError('command objects are not list snapshots')
        if kind not in ('table','chain','rule'):
            report.add('object_scope','OPEN',where,'Unsupported list object '+kind);continue
        family=string(obj.get('family'),'family');table=string(obj.get('name') if kind=='table' else obj.get('table'),'table')
        if family not in ('ip','ip6','inet','arp','bridge','netdev'):raise InputError('unknown family')
        if kind=='table':
            key=(family,table)
            if key in tables:raise InputError('duplicate table')
            tables[key]=obj
            flags=obj.get('flags',[])
            if not isinstance(flags,list):raise InputError('table.flags must be array')
            for flag in flags:
                string(flag,'table flag')
                if flag not in ('dormant','owner','persist'):
                    report.add('table_flags','OPEN',where,'Unknown table flag prevents complete structural assessment')
            if 'dormant' in flags:report.add('table_active','OPEN',where,'Dormant table is not active protection')
        elif kind=='chain':
            key=(family,table,string(obj.get('name'),'chain.name'))
            if key in chains:raise InputError('duplicate chain')
            chains[key]=obj
        else:
            string(obj.get('chain'),'rule.chain');sequence(obj.get('expr'),'rule.expr');rules.append((obj,where))
    protection=set()
    for key,chain in chains.items():
        family,table,name=key
        if (family,table) not in tables:report.add('references','OPEN',repr(key),'Missing owning table')
        if chain.get('hook') in ('input','forward'):
            policy=chain.get('policy')
            if policy not in ('accept','drop'):report.add('chain_policy','OPEN',repr(key),'No supported explicit base-chain policy')
            else:report.check('chain_policy',policy=='drop',repr(key),'Default '+str(chain.get('hook'))+' policy '+policy)
            if chain.get('type')!='filter':report.add('chain_type','OPEN',repr(key),'Ingress chain is not explicitly filter type')
            if type(chain.get('prio')) is not int:report.add('priority','OPEN',repr(key),'No numeric hook priority')
            if chain.get('hook')=='input' and policy=='drop' and chain.get('type')=='filter' and (family,table) in tables and 'dormant' not in tables[(family,table)].get('flags',[]):
                protection.update(('ip','ip6') if family=='inet' else (family,))
    for family in ('ip','ip6'):
        report.add('family_coverage','PASS' if family in protection else 'OPEN',family,'Declared default-drop input chain' if family in protection else 'Missing active default-drop input chain')
    for rule,where in rules:
        key=(rule['family'],rule['table'],rule['chain']);chain=chains.get(key)
        if chain is None:report.add('references','OPEN',where,'Rule chain missing');continue
        if chain.get('hook') not in ('input','forward'):
            report.add('chain_flow','OPEN',where,'Non-ingress chain reachability not simulated');continue
        constraints=set();unknown=False;accept=False
        for statement in rule['expr']:
            mapping(statement,'rule statement')
            if len(statement)!=1:raise InputError('statement must have one expression')
            kind,value=next(iter(statement.items()))
            if kind=='match':
                constraint=restricted(value)
                if constraint:constraints.add(constraint)
                else:unknown=True;report.add('expression','OPEN',where,'Unsupported match cannot narrow an accept finding')
            elif kind=='counter':
                if isinstance(value,str):
                    if not string(value,'counter name'):raise InputError('empty counter name')
                    report.add('counter_reference','OPEN',where,'Named counter definition is outside supported object scope')
                elif isinstance(value,dict):
                    if set(value)-{'packets','bytes'}:report.add('counter_attributes','OPEN',where,'Unknown counter attributes')
                    for field in ('packets','bytes'):
                        if field in value and (type(value[field]) is not int or not 0<=value[field]<2**64):
                            raise InputError('counter values must be unsigned 64-bit integers')
                else:raise InputError('counter statement requires object or nonempty name')
            elif kind in ('log','comment'):
                unknown=True
                report.add('expression','OPEN',where,'Log/comment statement semantics are outside the selected structural profile')
            elif kind in ('accept','drop'):
                if value is not None:raise InputError(kind+' verdict must be null')
                if kind=='accept':accept=True
            elif kind=='reject':
                if value is not None and not isinstance(value,dict):raise InputError('reject requires null or object')
                if isinstance(value,dict) and not set(value).issubset({'type','expr'}):report.add('reject_semantics','OPEN',where,'Unknown reject attributes')
            else:unknown=True;report.add('expression','OPEN',where,'Unsupported verdict/expression '+kind)
        if accept:
            report.check('unrestricted_accept',bool(constraints),where,'Accept requires validated state/interface/source/port constraints')
            if constraints and 'state' not in constraints and 'interface' not in constraints and 'source' not in constraints:
                report.add('service_exposure','OPEN',where,'Port-only accept exposes service to unrestricted sources')
            if unknown:report.add('accept_flow','OPEN',where,'Accept rule has unsupported expressions')
        if not rule['expr']:report.add('empty_rule','OPEN',where,'No rule expressions')
    return report.finish(LIMITS)
