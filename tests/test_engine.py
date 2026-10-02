# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import unittest
from nft_ingress_audit import analyze
from nft_ingress_audit.common import InputError

class NftTests(unittest.TestCase):
    def good(self):return {'nftables':[{'metainfo':{'json_schema_version':1}},{'table':{'family':'inet','name':'filter'}},{'chain':{'family':'inet','table':'filter','name':'input','hook':'input','type':'filter','prio':0,'policy':'drop'}},{'rule':{'family':'inet','table':'filter','chain':'input','expr':[{'match':{'op':'==','left':{'ct':{'key':'state'}},'right':{'set':['established','related']}}},{'accept':None}]}}]}
    def test_positive(self):self.assertEqual(analyze(self.good())['status'],'PASS')
    def test_open_accept(self):
        s=self.good();s['nftables'][-1]['rule']['expr']=[{'accept':None}];self.assertEqual(analyze(s)['status'],'FAIL')
    def test_default_accept(self):
        s=self.good();s['nftables'][2]['chain']['policy']='accept';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_dormant_not_coverage(self):
        s=self.good();s['nftables'][1]['table']['flags']=['dormant'];self.assertEqual(analyze(s)['status'],'OPEN')
    def test_zero_prefix_not_restriction(self):
        s=self.good();s['nftables'][-1]['rule']['expr'][0]['match']={'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'0.0.0.0/0'};self.assertEqual(analyze(s)['status'],'FAIL')
    def test_missing_ipv6(self):
        s=self.good()
        for wrapper in s['nftables'][1:]:next(iter(wrapper.values()))['family']='ip'
        self.assertEqual(analyze(s)['status'],'OPEN')
    def test_unknown_expression(self):
        s=self.good();s['nftables'][-1]['rule']['expr'].insert(0,{'future':None});self.assertEqual(analyze(s)['status'],'OPEN')
    def test_command_not_snapshot(self):
        with self.assertRaises(InputError):analyze({'nftables':[{'flush':{'ruleset':None}}]})
    def test_duplicate_chain(self):
        s=self.good();s['nftables'].append(s['nftables'][2])
        with self.assertRaises(InputError):analyze(s)
    def test_wrong_match_type(self):
        s=self.good();s['nftables'][-1]['rule']['expr'][0]['match']['left']=[]
        with self.assertRaises(InputError):analyze(s)

    def test_selector_types_and_extra_attributes(self):
        cases=[({'key':'iifname'},123),({'key':'iif'},'eth0'),({'key':'iif'},0),({'key':'iifname','future':1},'eth0')]
        for selector,value in cases:
            s=self.good();s['nftables'][-1]['rule']['expr'][0]['match']={'op':'==','left':{'meta':selector},'right':value}
            self.assertEqual(analyze(s)['status'],'FAIL')
    def test_verdict_requires_null(self):
        s=self.good();s['nftables'][-1]['rule']['expr'][-1]={'accept':{}}
        with self.assertRaises(InputError):analyze(s)
