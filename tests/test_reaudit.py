import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from nft_ingress_audit import analyze
from nft_ingress_audit.common import InputError
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,expected):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'case.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','nft_ingress_audit',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,expected,r.stderr)
            self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_invalid_counter_shapes_and_values_rejected(self):
        for counter in ([],None,True,{'packets':True,'bytes':0},{'packets':0,'bytes':-1},{'bytes':2**64}):
            s=self.good();s['nftables'][-1]['rule']['expr'].insert(0,{'counter':counter})
            with self.assertRaises(InputError):analyze(s)
            self.assertEqual(self.cli(s,2)['status'],'ERROR')
    def test_counter_and_unsupported_neutral_statements(self):
        s=self.good();s['nftables'][-1]['rule']['expr'].insert(0,{'counter':{'packets':0,'bytes':123}})
        self.assertEqual(analyze(s)['status'],'PASS');self.assertEqual(self.cli(s,0)['status'],'PASS')
        for statement in ({'log':{}},{'comment':{}},{'counter':'named'},{'counter':{'future':1}}):
            s=self.good();s['nftables'][-1]['rule']['expr'].insert(0,statement)
            self.assertEqual(analyze(s)['status'],'OPEN');self.assertEqual(self.cli(s,3)['status'],'OPEN')
    def test_unknown_table_flag_and_prefix_attributes_stay_open(self):
        s=self.good();s['nftables'][1]['table']['flags']=['future']
        self.assertEqual(analyze(s)['status'],'OPEN');self.assertEqual(self.cli(s,3)['status'],'OPEN')
        s=self.good();s['nftables'][-1]['rule']['expr'][0]['match']={'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':{'prefix':{'addr':'192.0.2.0','len':24,'future':1}}}
        self.assertNotEqual(analyze(s)['status'],'PASS');self.cli(s,1)
