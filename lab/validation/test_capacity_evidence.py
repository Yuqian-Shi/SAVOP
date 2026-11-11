"""Negative evidence tests; corrupt in memory, never change saved artifacts."""
import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import verify_capacity


@unittest.skipUnless(os.environ.get("CAPACITY_EVIDENCE_RUN"),
                     "requires an external frozen capacity evidence bundle; not an offline unit fixture")
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.run = Path(os.environ["CAPACITY_EVIDENCE_RUN"])

    def reject(self, name, mutate):
        original = verify_capacity.read

        def changed(path):
            data = original(path)
            if path.name == name:
                data = copy.deepcopy(data)
                mutate(data)
            return data

        with patch.object(verify_capacity, "read", changed), self.assertRaises(AssertionError):
            verify_capacity.check_run(self.run)

    def test_baseline(self):
        self.assertTrue(verify_capacity.check_run(self.run)["qualified"])

    def test_not_ten_nodes_same_as(self):
        self.reject("scene.json", lambda x: x["devices"]["2"].update({"as": 4200000999}))

    def test_duplicate_namespace(self):
        self.reject("ownership.json", lambda x: x["2"].update(netns_inode=x["1"]["netns_inode"]))

    def test_missing_reply(self):
        self.reject("packets-final.json", lambda x: x[0].update(received=[]))

    def test_uninstalled_table(self):
        self.reject("observation-steady-final.json", lambda x: x[0]["auto"].update(installed_fingerprint=None))

    def test_silent_refresh_error(self):
        self.reject("observation-steady-final.json", lambda x: x[0]["auto"].update(error_count=1000))

    def test_host_route_change(self):
        self.reject("result.json", lambda x: x["host_after"]["routes4"].append({"dst": "198.19.0.0/16"}))


if __name__ == "__main__":
    unittest.main()
