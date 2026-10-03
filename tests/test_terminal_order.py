# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from nft_ingress_audit import analyze
from nft_ingress_audit.common import InputError

PROJECT = Path(__file__).resolve().parents[1]


class TerminalOrderTests(unittest.TestCase):
    def snapshot(self, statements):
        snapshot = json.loads((PROJECT / 'examples/good.json').read_text())
        snapshot['nftables'][-1]['rule']['expr'] = statements
        return snapshot

    def restriction(self):
        return {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '192.0.2.0/24'}}

    def cli(self, snapshot):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.json'
            raw = json.dumps(snapshot).encode()
            path.write_bytes(raw)
            result = subprocess.run([sys.executable, '-m', 'nft_ingress_audit', str(path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(path.read_bytes(), raw)
            self.assertNotIn('Traceback', result.stderr)
            return result.returncode, json.loads(result.stdout)

    def test_match_before_accept_stays_valid(self):
        snapshot = self.snapshot([self.restriction(), {'accept': None}])
        self.assertEqual(analyze(snapshot)['status'], 'PASS')
        self.assertEqual(self.cli(snapshot)[0], 0)

    def test_match_after_accept_cannot_narrow(self):
        snapshot = self.snapshot([{'accept': None}, self.restriction()])
        with self.assertRaises(InputError):
            analyze(snapshot)
        code, report = self.cli(snapshot)
        self.assertEqual((code, report['status']), (2, 'ERROR'))

    def test_statement_after_each_terminal_is_rejected(self):
        for verdict in ({'accept': None}, {'drop': None}, {'reject': {}}, {'return': None}, {'jump': {'target': 'next'}}, {'goto': {'target': 'next'}}):
            with self.subTest(verdict=verdict):
                snapshot = self.snapshot([verdict, {'counter': {'packets': 0, 'bytes': 0}}])
                with self.assertRaises(InputError):
                    analyze(snapshot)
                self.assertEqual(self.cli(snapshot)[0], 2)

    def test_multiple_terminal_verdicts_are_rejected(self):
        for first in ({'accept': None}, {'drop': None}, {'reject': {}}):
            for last in ({'accept': None}, {'drop': None}, {'reject': {}}):
                with self.subTest(first=first, last=last):
                    with self.assertRaises(InputError):
                        analyze(self.snapshot([self.restriction(), first, last]))

    def test_final_unsupported_transfer_remains_open(self):
        for verdict in ({'return': None}, {'jump': {'target': 'next'}}, {'goto': {'target': 'next'}}):
            snapshot = self.snapshot([self.restriction(), verdict])
            self.assertEqual(analyze(snapshot)['status'], 'OPEN')
            self.assertEqual(self.cli(snapshot)[0], 3)

    def test_final_supported_nonaccept_stays_valid(self):
        for verdict in ({'drop': None}, {'reject': None}, {'reject': {}}):
            snapshot = self.snapshot([self.restriction(), verdict])
            self.assertEqual(analyze(snapshot)['status'], 'PASS')
            self.assertEqual(self.cli(snapshot)[0], 0)

    def test_reject_type_requires_string(self):
        for value in (None, [], {}, True, 1):
            snapshot = self.snapshot([{'reject': {'type': value}}])
            with self.assertRaises(InputError):
                analyze(snapshot)
            self.assertEqual(self.cli(snapshot)[0], 2)

    def test_unknown_reject_type_remains_open(self):
        snapshot = self.snapshot([{'reject': {'type': 'not-a-native-reject-kind'}}])
        self.assertEqual(analyze(snapshot)['status'], 'OPEN')
        self.assertEqual(self.cli(snapshot)[0], 3)

    def test_explicit_unmodeled_reject_expression_remains_open(self):
        for value in ({'future': True}, [], {}, None, 0, 'host-unreachable'):
            snapshot = self.snapshot([{'reject': {'type': 'icmpx', 'expr': value}}])
            self.assertEqual(analyze(snapshot)['status'], 'OPEN')
            self.assertEqual(self.cli(snapshot)[0], 3)
