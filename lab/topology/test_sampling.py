"""Small, hand-checkable counterexamples for the AS sampling pipeline."""
from collections import Counter
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import networkx as nx

import sample_topologies as s
from motif_topologies import sample_motifs


def fixture(reverse=False):
    graph = nx.Graph()
    rows = [(1, 2, "p2c", 1), (1, 3, "p2c", 1), (2, 3, "p2p", 0),
            (2, 4, "p2c", 2), (3, 4, "p2c", 3), (3, 5, "unknown", 0),
            (4, 5, "p2p", 0), (4, 6, "conflict", 0), (5, 7, "p2c", 5)]
    for a, b, relation, provider in reversed(rows) if reverse else rows:
        graph.add_edge(a, b, u=a, v=b, relation=relation, provider=provider,
                       inferred_sources=["caida"] if relation in ("p2p", "p2c", "conflict") else [],
                       observed_sources=["ris"])
    graph.add_node(8)
    roles = s.relationship_counts(graph)
    for n in graph:
        row = {"asn": n, "degree": graph.degree(n), **{k: roles[n][k] for k in ("providers", "customers", "peers", "unknown")}}
        row.update(full_role=s.role(row), stratum=s.stratum(row))
        graph.nodes[n].update(row)
    return graph


class Sampling(unittest.TestCase):
    def setUp(self):
        self.graph = fixture()
        self.eligible = self.graph.subgraph(set(range(1, 8)))

    def test_exact_size_connected(self):
        for size in range(1, 8):
            ids, _ = s.sample_nodes(self.eligible, size, 123)
            self.assertEqual(len(set(ids)), size)
            self.assertTrue(nx.is_connected(self.eligible.subgraph(ids)))

    def test_reproducible(self):
        self.assertEqual(s.sample_nodes(self.eligible, 5, 123), s.sample_nodes(self.eligible, 5, 123))

    def test_insertion_order_invariant(self):
        other = fixture(True).subgraph(set(range(1, 8)))
        self.assertEqual(s.sample_nodes(self.eligible, 5, 123), s.sample_nodes(other, 5, 123))

    def test_seed_changes_selection(self):
        selections = {tuple(s.sample_nodes(self.eligible, 4, k)[0]) for k in range(20)}
        self.assertGreater(len(selections), 1)

    def test_oversize_rejected(self):
        with self.assertRaises(ValueError):
            s.sample_nodes(self.eligible, 8, 123)

    def test_zero_rejected(self):
        with self.assertRaises(ValueError):
            s.sample_nodes(self.eligible, 0, 123)

    def test_noninteger_rejected(self):
        for n, seed in ((2.0, 1), (2, True), (True, 1)):
            with self.assertRaises(ValueError):
                s.sample_nodes(self.eligible, n, seed)

    def test_disconnected_rejected(self):
        with self.assertRaises(ValueError):
            s.sample_nodes(self.graph, 3, 123)

    def test_quotas_sum(self):
        groups = {"a": list(range(7)), "b": [8, 9], "c": [10]}
        for n in range(1, 11):
            q = s.quotas(groups, n)
            self.assertEqual(sum(q.values()), n)
            self.assertTrue(all(q[k] <= len(groups[k]) for k in q))

    def test_largest_component_exclusions(self):
        ids, sizes = s.largest_component(self.graph)
        self.assertEqual(ids, set(range(1, 8)))
        self.assertEqual(sizes, [7, 1])

    def test_largest_component_tie(self):
        g = nx.Graph([(5, 6), (1, 2)])
        self.assertEqual(s.largest_component(g)[0], {1, 2})

    def test_unknown_conflict_not_active_in_known(self):
        g = s.domain_graph(self.graph, "known")
        self.assertFalse(g.has_edge(3, 5))
        self.assertFalse(g.has_edge(4, 6))
        self.assertTrue(g.has_node(6))
        self.assertEqual(g.nodes[3]["degree"], self.graph.nodes[3]["degree"])

    def test_unknown_retained_in_union(self):
        self.assertEqual(s.domain_graph(self.graph, "union")[3][5]["relation"], "unknown")

    def test_full_source_role_not_recategorized(self):
        sample, _, _, _ = s.make_sample(self.graph, self.eligible, "union", "ipv4", 2, 1, "a" * 64)
        for row in sample["nodes"]:
            self.assertEqual(row["full_role"], self.graph.nodes[row["asn"]]["full_role"])
            self.assertEqual(row["providers"], self.graph.nodes[row["asn"]]["providers"])

    def test_induced_and_cut_edges_exact(self):
        sample, boundary, _, _ = s.make_sample(self.graph, self.eligible, "union", "ipv4", 4, 11, "a" * 64)
        ids = {r["asn"] for r in sample["nodes"]}
        actual = {(r["u"], r["v"]) for r in sample["edges"]}
        cut = {(r["u"], r["v"]) for r in boundary}
        self.assertEqual(actual, {(u, v) for u, v in self.graph.edges if u in ids and v in ids})
        self.assertEqual(cut, {(u, v) for u, v in self.graph.edges if (u in ids) != (v in ids)})
        self.assertEqual(sum(r["boundary_degree"] for r in sample["nodes"]), len(boundary))

    def test_known_keeps_inactive_evidence(self):
        known = s.domain_graph(self.graph, "known")
        component, _ = s.largest_component(known)
        sample, _, _, _ = s.make_sample(self.graph, known.subgraph(component), "known", "ipv4", len(component), 1, "a" * 64)
        edge = next(r for r in sample["edges"] if (r["u"], r["v"]) == (3, 5))
        self.assertFalse(edge["active"])
        self.assertEqual(edge["relation"], "unknown")

    def test_provider_direction(self):
        roles = s.relationship_counts(self.graph)
        self.assertEqual(roles[4]["providers"], 2)
        self.assertEqual(roles[1]["customers"], 2)

    def test_control_quotas_exact(self):
        _, info = s.sample_nodes(self.eligible, 5, 123)
        control = Counter(self.graph.nodes[n]["stratum"] for n in info["uniform_control_asns"])
        self.assertEqual(dict(control), {k: v for k, v in info["target_strata"].items() if v})

    def test_hops_disconnected_are_reported(self):
        result = s.graph_metrics(self.graph, include_hops=True)
        self.assertEqual(result["unreachable_unordered_pairs"], 7)

    def test_total_variation_bounds(self):
        self.assertEqual(s.histogram_distance({"a": 3}, {"b": 2}), 1)
        self.assertEqual(s.histogram_distance({"a": 3}, {"a": 2}), 0)
        self.assertIsNone(s.histogram_distance({}, {"b": 2}))

    def test_existing_json_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sentinel.json"
            s.dump(p, {"keep": True})
            before = p.read_bytes()
            with self.assertRaises(FileExistsError):
                s.dump(p, {})
            self.assertEqual(p.read_bytes(), before)

    def test_bad_domain(self):
        with self.assertRaises(ValueError):
            s.domain_graph(self.graph, "invent-peer")


class Motifs(unittest.TestCase):
    def setUp(self):
        self.graph = nx.Graph()
        for n in range(1, 11):
            nxt = n % 10 + 1
            u, v = sorted((n, nxt))
            self.graph.add_edge(u, v, u=u, v=v, relation="p2p", provider=0, inferred_sources=["test"], observed_sources=[])
        for n in range(11, 51):
            for p in (n % 10 + 1, (n + 1) % 10 + 1):
                self.graph.add_edge(p, n, u=p, v=n, relation="p2c", provider=p, inferred_sources=["test"], observed_sources=[])
        roles = s.relationship_counts(self.graph)
        for n in self.graph:
            row = {"asn": n, "degree": self.graph.degree(n), **{k: roles[n][k] for k in ("providers", "customers", "peers", "unknown")}}
            row.update(full_role=s.role(row), stratum=s.stratum(row))
            self.graph.nodes[n].update(row)

    def test_exact_size_connected_with_motifs(self):
        for seed in (1, 2, 3):
            ids, audit = sample_motifs(self.graph, 20, seed)
            self.assertEqual(len(ids), 20)
            self.assertTrue(nx.is_connected(self.graph.subgraph(ids)))
            self.assertEqual(len(audit["motif_anchors"]), 2)
            for a in audit["motif_anchors"]:
                self.assertIn(a["asn"], ids)
                self.assertEqual(len(set(a["providers"])), 2)
                for p in a["providers"]:
                    self.assertIn(p, ids)
                    self.assertEqual(self.graph[p][a["asn"]]["provider"], p)

    def test_deterministic(self):
        self.assertEqual(sample_motifs(self.graph, 20, 1), sample_motifs(self.graph, 20, 1))

    def test_insertion_order_invariant(self):
        other = nx.Graph()
        other.add_nodes_from(reversed(list(self.graph.nodes(data=True))))
        other.add_edges_from(reversed(list(self.graph.edges(data=True))))
        self.assertEqual(sample_motifs(self.graph, 20, 1), sample_motifs(other, 20, 1))

    def test_unknown_fails_closed(self):
        self.graph[1][2]["relation"] = "unknown"
        with self.assertRaises(ValueError):
            sample_motifs(self.graph, 20, 1)

    def test_insufficient_candidates(self):
        for _, _, d in self.graph.edges(data=True):
            d["relation"], d["provider"] = "p2p", 0
        with self.assertRaises(ValueError):
            sample_motifs(self.graph, 20, 1)

    def test_too_small_fails(self):
        with self.assertRaises(ValueError):
            sample_motifs(self.graph, 5, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
