"""Pure fixture and readiness checks; no containers or host mutations."""
import unittest
from collections import Counter

from run_capacity import topology, prefix, address, stability_start, installed_and_fresh
from capacity_probe import check_address


class CapacityTests(unittest.TestCase):
    def test_ten_real_devices_per_as(self):
        for count in (1, 5, 20, 100):
            scene, edges = topology(count, 4)
            sizes = Counter(v["as"] for v in scene["devices"].values())
            self.assertEqual(len(sizes), count)
            self.assertEqual(set(sizes.values()), {10})
            self.assertEqual(len(edges), 10 * count - 1)

    def test_connected_tree(self):
        for count in (1, 5, 100):
            scene, edges = topology(count, 4)
            seen, pending = {1}, [1]
            while pending:
                node = pending.pop()
                for a, b in edges:
                    if node in (a, b):
                        other = b if a == node else a
                        if other not in seen:
                            seen.add(other)
                            pending.append(other)
            self.assertEqual(len(seen), len(scene["devices"]))

    def test_unique_lab_prefixes(self):
        for family in (4, 6):
            self.assertEqual(len({prefix(n, family) for n in range(1, 1001)}), 1000)
            for n in range(1, 1001):
                check_address(address(n, family))

    def test_reject_external(self):
        for value in ("8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"):
            with self.assertRaises(ValueError):
                check_address(value)

    def test_readiness_transition_without_fib_change(self):
        since = stability_start(False, "same", "same", None, 1)
        self.assertIsNone(since)
        since = stability_start(True, "same", "same", since, 2)
        self.assertEqual(since, 2)
        self.assertEqual(stability_start(True, "same", "same", since, 6), 2)

    def test_change_resets_stability(self):
        self.assertEqual(stability_start(True, "new", "old", 1, 5), 5)
        self.assertIsNone(stability_start(False, "same", "same", 1, 5))

    def test_checking_requires_recent_verified_install(self):
        state = {"phase": "checking", "paused": False, "enabled": True, "dry_run": False,
                 "last_error": None, "last_hash": 3, "installed_fingerprint": 7,
                 "refresh_count": 1, "last_verified": 20}
        self.assertTrue(installed_and_fresh(state, 21))
        for key, value in (("last_hash", None), ("installed_fingerprint", None),
                           ("refresh_count", 0), ("last_error", "failed"), ("paused", True),
                           ("dry_run", True), ("last_verified", 1), ("phase", "retry_wait")):
            self.assertFalse(installed_and_fresh(dict(state, **{key: value}), 21))


if __name__ == "__main__":
    unittest.main()
