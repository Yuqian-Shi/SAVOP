import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_ts01_bgp01


EXAMPLE = Path(__file__).resolve().parents[2] / 'examples/evidence/ts01-release-r1'


@unittest.skipUnless((EXAMPLE / 'result.json').is_file(), 'requires the bundled release evidence example')
class PublicEvidenceTests(unittest.TestCase):
    def audit_with(self, name, mutate):
        original = verify_ts01_bgp01.load

        def changed(path):
            value = original(path)
            if path.name == name:
                value = copy.deepcopy(value)
                mutate(value)
            return value

        with patch.object(verify_ts01_bgp01, 'load', side_effect=changed):
            return verify_ts01_bgp01.audit(EXAMPLE / 'result.json')

    def rejected(self, report, check):
        self.assertEqual(report['outcome'], 'failed')
        self.assertFalse(next(row['pass'] for row in report['checks'] if row['name'] == check))

    def test_baseline(self):
        report = verify_ts01_bgp01.audit(EXAMPLE / 'result.json')
        self.assertEqual((report['checks_passed'], report['checks_total']), (44, 44))

    def test_wrong_source_rejected(self):
        def mutate(result):
            probe = next(row for row in result['probe_results'] if row['received_packets'])
            probe['received_packets'][0]['source'] = '192.0.2.99'
        self.rejected(self.audit_with('result.json', mutate), 'raw_packet_matrix')

    def test_duplicate_packet_rejected(self):
        def mutate(result):
            probe = next(row for row in result['probe_results'] if len(row['received_packets']) > 1)
            probe['received_packets'][1] = copy.deepcopy(probe['received_packets'][0])
        self.rejected(self.audit_with('result.json', mutate), 'raw_packet_matrix')

    def test_changed_counter_rejected(self):
        def mutate(result):
            result['probe_results'][0]['drop_counter_after'] += 1
        self.rejected(self.audit_with('result.json', mutate), 'raw_packet_matrix')

    def test_unexpected_peer_even_with_new_fingerprint_rejected(self):
        def mutate(state):
            state['fingerprint']['routers']['11']['bgp'].append('dsav_11_21')
            state['state_sha256'] = hashlib.sha256(json.dumps(state['fingerprint'], sort_keys=True).encode()).hexdigest()
        self.rejected(self.audit_with('state-peer-down.json', mutate), 'all_router_bgp_and_fib:peer-down')

    def test_claimed_success_is_not_sufficient(self):
        def mutate(result):
            result['route_arm_fingerprint_checks'][0]['actual'] = '0' * 64
        self.rejected(self.audit_with('result.json', mutate), 'runner_fingerprint_assertions')


if __name__ == '__main__':
    unittest.main()
