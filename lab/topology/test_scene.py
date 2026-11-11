from copy import deepcopy
import ipaddress
import unittest

from compile_scene import compile_sample
from sample_topologies import make_sample
from motif_topologies import sample_motifs
import test_sampling


class SceneTests(unittest.TestCase):
    def setUp(self):
        fixture = test_sampling.Motifs()
        fixture.setUp()
        self.sample, _, _, _ = make_sample(fixture.graph, fixture.graph, "known", "ipv4", 20, 1, "a" * 64, sample_motifs)

    def test_unique_private_as_mapping(self):
        base, matrix = compile_sample(self.sample)
        self.assertEqual(len(base["devices"]), 20)
        self.assertEqual(len({d["as"] for d in base["devices"].values()}), 20)
        self.assertTrue(all(4200000000 <= d["as"] <= 4294967294 for d in base["devices"].values()))
        self.assertEqual({m["source_asn"] for m in matrix["mapping"]}, {n["asn"] for n in self.sample["nodes"]})

    def test_ipv4_lab_prefixes_not_source_prefixes(self):
        base, _ = compile_sample(self.sample)
        nets = [ipaddress.ip_network(p) for d in base["devices"].values() for p in d["prefixes"]]
        self.assertTrue(all(n.subnet_of(ipaddress.ip_network("198.18.0.0/15")) for n in nets))
        self.assertEqual(len(set(nets)), 20)

    def test_ipv6(self):
        self.sample["layer"] = "ipv6"
        base, _ = compile_sample(self.sample)
        self.assertEqual(base["auto_ip_version"], 6)
        self.assertTrue(all(ipaddress.ip_network(p).version == 6 for d in base["devices"].values() for p in d["prefixes"]))

    def test_all_relationships_explicit(self):
        base, _ = compile_sample(self.sample)
        self.assertEqual(len(base["links"]), len(base["routing_policy"]["links"]))
        for r in base["routing_policy"]["links"]:
            self.assertTrue(r["relationship"] == "p2p" and r["provider"] is None or r["relationship"] == "p2c" and r["provider"] in (r["a"], r["b"]))

    def test_unknown_active_rejected(self):
        self.sample["edges"][0]["relation"] = "unknown"
        with self.assertRaises(ValueError):
            compile_sample(self.sample)

    def test_inactive_unknown_retained(self):
        # Keep the active graph connected after disabling one cycle edge.
        for edge in self.sample["edges"]:
            if edge["relation"] == "p2p":
                edge["relation"], edge["active"] = "unknown", False
                break
        _, matrix = compile_sample(self.sample)
        self.assertEqual(len(matrix["inactive_source_edges"]), 1)

    def test_duplicate_node_rejected(self):
        self.sample["nodes"].append(deepcopy(self.sample["nodes"][0]))
        with self.assertRaises(ValueError):
            compile_sample(self.sample)

    def test_duplicate_edge_rejected(self):
        self.sample["edges"].append(deepcopy(self.sample["edges"][0]))
        with self.assertRaises(ValueError):
            compile_sample(self.sample)

    def test_bad_provider_rejected(self):
        edge = next(e for e in self.sample["edges"] if e["relation"] == "p2c")
        edge["provider"] = 999999
        with self.assertRaises(ValueError):
            compile_sample(self.sample)

    def test_disconnected_rejected(self):
        victim = self.sample["nodes"][0]["asn"]
        self.sample["edges"] = [e for e in self.sample["edges"] if victim not in (e["u"], e["v"])]
        with self.assertRaises(ValueError):
            compile_sample(self.sample)

    def test_anycast_is_explicit_and_separate(self):
        base, matrix = compile_sample(self.sample)
        anycast = next(c for c in matrix["cases"] if c["mode"] == "anycast")
        self.assertEqual(len({r["lab_asn"] for r in anycast["origin_nodes"]}), 2)
        self.assertTrue(all(anycast["prefix"] not in d["prefixes"] for d in base["devices"].values()))
        self.assertTrue(any(c["mode"] == "multihoming" for c in matrix["cases"]))

    def test_roles_distinct_per_placement(self):
        _, matrix = compile_sample(self.sample)
        for c in matrix["cases"]:
            if c["mode"] == "unicast":
                self.assertEqual(len({c[k]["lab_asn"] for k in ("victim", "attacker", "reflector")}), 3)

    def test_deployment_arms_are_explicit_and_baseline_is_empty(self):
        base, matrix = compile_sample(self.sample)
        adjacency = {n: set() for n in base["devices"]}
        for a, b, _ in base["links"]:
            adjacency[a].add("eth_" + b)
            adjacency[b].add("eth_" + a)
        for case in matrix["cases"]:
            arms = case["deployment_arms"]
            self.assertEqual(len(arms), 3)
            self.assertEqual(arms[0]["targets"], [])
            self.assertIsNone(arms[0]["mechanism"])
            for arm in arms[1:]:
                self.assertIn(arm["mechanism"], ("strict_urpf", "loose_urpf"))
                self.assertEqual(arm["deployment_fraction"], len(arm["targets"]) / len(base["devices"]))
                for target in arm["targets"]:
                    self.assertEqual(set(target["ingress_interfaces"]), adjacency[target["node_id"]])
                    self.assertEqual(target["lab_asn"], base["devices"][target["node_id"]]["as"])

    def test_deployment_matches_case_roles(self):
        _, matrix = compile_sample(self.sample)
        for case in matrix["cases"]:
            roles = [case["victim"]] if case["mode"] == "unicast" else case["provider_nodes"] if case["mode"] == "multihoming" else case["origin_nodes"]
            self.assertEqual({n["node_id"] for n in roles}, {n["node_id"] for n in case["deployment_arms"][1]["targets"]})
        self.assertFalse(matrix["deployment_contract"]["data_plane_auto"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
