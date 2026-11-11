"""Container bookkeeping negatives without invoking Docker or host APIs."""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import threading
import unittest
from unittest.mock import Mock

from run_capacity import CapacityLab
from run_five_as import LABEL


class CreationTests(unittest.TestCase):
    def lab(self):
        lab=CapacityLab.__new__(CapacityLab)
        lab.args=SimpleNamespace(run_id='cap-unit-test')
        lab.root=Path('/mnt/hdd/k5-capacity-unit')
        lab.generated=lab.root/'savop_run_cap-unit-test'
        lab.report={'image':'sha256:fixed'}
        lab.nodes={}
        lab.namespace_fds={}
        lab.creation_lock=threading.Lock()
        lab.guard=Mock()
        return lab

    def test_existing_name_is_never_claimed(self):
        lab=self.lab()
        lab.inspect=Mock(return_value={'Id':'other'})
        lab.command=Mock()
        with self.assertRaisesRegex(RuntimeError,'already exists'):
            lab.create_node(1)
        lab.command.assert_not_called()
        self.assertFalse(lab.nodes)

    def test_timeout_recovers_only_matching_label(self):
        for label in ('cap-unit-test','someone-else'):
            lab=self.lab()
            lab.inspect=Mock(side_effect=[None,{'Id':'full-id','Config':{'Labels':{LABEL:label}}}])
            lab.command=Mock(side_effect=subprocess.TimeoutExpired(['docker','run'],45))
            with self.assertRaises(subprocess.TimeoutExpired):
                lab.create_node(3)
            self.assertEqual(bool(lab.nodes),label=='cap-unit-test')
            if lab.nodes:
                self.assertEqual(lab.nodes[3]['id'],'full-id')
            self.assertFalse(lab.namespace_fds)

    def test_missing_partial_is_not_registered(self):
        lab=self.lab()
        lab.inspect=Mock(return_value=None)
        lab.command=Mock(side_effect=RuntimeError('docker failed'))
        with self.assertRaisesRegex(RuntimeError,'docker failed'):
            lab.create_node(1)
        self.assertFalse(lab.nodes)

    def test_resource_guard_runs_before_name_check(self):
        lab=self.lab()
        lab.guard=Mock(side_effect=RuntimeError('reserve'))
        lab.inspect=Mock()
        with self.assertRaisesRegex(RuntimeError,'reserve'):
            lab.create_node(1)
        lab.inspect.assert_not_called()
        self.assertFalse(lab.nodes)


if __name__=='__main__':
    unittest.main()
