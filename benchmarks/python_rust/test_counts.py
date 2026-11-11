"""Cardinality regression for the fixed benchmark fixtures, not algorithm tests."""
import itertools
import unittest
from run_incremental import expected_counts


class CountTests(unittest.TestCase):
    def test_cardinality_even_and_odd_loops(self):
        for app, mode, loops in itertools.product(
            ("strict_urpf", "loose_urpf", "fp_urpf"), ("full", "update"), (1, 2, 3, 4, 10, 100)
        ):
            with self.subTest(app=app, mode=mode, loops=loops):
                counts = []
                for index in range(loops):
                    state = (index + 1) % 2 if mode == "update" else 0
                    interfaces = {"eth0", "eth1", "eth2", "eth3"}
                    if state:
                        interfaces.add("eth4")
                    counts.append(1000 * (len(interfaces) if app == "fp_urpf" else 1))
                self.assertEqual(expected_counts(dict(app=app, mode=mode, iterations=loops,
                                                      input_routes=1000)), (counts[-1], sum(counts)))


if __name__ == "__main__":
    unittest.main()
