"""Offline tests with intentionally invalid data; never access the public network."""
import bz2
import gzip
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from build_map import SCHEMA, inspect_mrt, materialize, normalize_path, parse_rel, public_asn
from serve_map import neighborhood


class Paths(unittest.TestCase):
    def test_prepend(self):
        self.assertEqual(normalize_path("174 174 3356 4134 4134"), ((174, 3356, 4134), None))

    def test_single_origin(self):
        self.assertEqual(normalize_path("4134"), ((4134,), None))

    def test_empty(self):
        self.assertEqual(normalize_path(None)[1], "empty_path")

    def test_sets_and_confederations(self):
        for p in ("174 {3356,4134}", "174 (3356 4134)", "174 [3356,4134]", "174 1.10"):
            self.assertEqual(normalize_path(p)[1], "set_confederation_or_nonsequence")

    def test_loops(self):
        self.assertEqual(normalize_path("174 3356 174")[1], "nonconsecutive_as_loop")

    def test_private_trans_reserved(self):
        for n in (0, 23456, 64496, 64512, 65534, 65535, 65536, 65551, 4200000000, 4294967295):
            self.assertFalse(public_asn(n))
        self.assertTrue(public_asn(4134))
        self.assertTrue(public_asn(132203))


class Relationships(unittest.TestCase):
    def parse(self, text, zipped=False):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / ("test.bz2" if zipped else "test.txt")
            if zipped:
                p.write_bytes(bz2.compress(text.encode()))
            else:
                p.write_text(text, encoding="utf-8")
            return parse_rel(p)

    def test_direction_preserved_when_asns_sorted(self):
        r, _ = self.parse("3356|174|-1\n")
        self.assertIn((174, 3356, "p2c", 3356), r)

    def test_symmetric_peer_deduplication(self):
        r, s = self.parse("174|3356|0\n3356|174|0\n")
        self.assertEqual(len(r), 1)
        self.assertEqual(s["counts"]["duplicate_claims"], 1)

    def test_conflicting_directions_not_overwritten(self):
        r, _ = self.parse("174|3356|-1\n3356|174|-1\n")
        self.assertEqual(len(r), 2)

    def test_bad_records_quarantined(self):
        _, s = self.parse("174|174|0\n174|3356|2\n174|3356|0|extra\n0|4134|0\nx|4134|0\n")
        self.assertEqual(s["counts"]["rejected"], 5)
        self.assertEqual(len(s["rejected"]), 5)

    def test_bz2_headers_and_step(self):
        r, s = self.parse("# step 1: peer\n174|3356|0\n", True)
        self.assertEqual(r[(174,3356,"p2p",0)], (2,"# step 1: peer"))
        self.assertEqual(len(s["headers"]), 1)


class Integrity(unittest.TestCase):
    def check(self, payload):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/"rib.gz"
            p.write_bytes(gzip.compress(payload))
            return inspect_mrt(p)

    @staticmethod
    def rib():
        # sequence=0, prefix /24 1.2.3, one entry, no attributes
        payload=struct.pack("!IB",0,24)+bytes((1,2,3))+struct.pack("!HHIH",1,0,0,0)
        return struct.pack("!IHHI",0,13,2,len(payload))+payload

    def test_count_independent_of_parser(self):
        self.assertEqual(self.check(self.rib())["expected_rib_entries"],1)

    def test_truncated_header(self):
        with self.assertRaises(ValueError):
            self.check(b"broken")

    def test_truncated_payload(self):
        with self.assertRaises(ValueError):
            self.check(self.rib()[:-1])

    def test_unknown_subtype_fail_closed(self):
        with self.assertRaises(ValueError):
            self.check(struct.pack("!IHHI",0,13,6,0))


class Graphs(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.row_factory=sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.executemany("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?)", [
            ("ipv4",174,3356,"p2c",3356,"a",1,"s"),
            ("ipv4",174,4134,"p2p",0,"a",2,"s"),
            ("ipv4",4134,4837,"p2c",4134,"a",3,"s"),
            ("ipv4",4134,4837,"p2c",4837,"b",1,"s")])
        self.db.execute("INSERT INTO observations VALUES(?,?,?,?,?,?,?)",("ipv4",4134,13335,"r",2,"4134 13335","1.1.1.0/24"))
        self.db.execute("INSERT INTO prefixes VALUES(?,?,?,?)",("ipv4",6939,"2.2.2.0/24","r"))
        self.report=materialize(self.db,"ipv4")

    def tearDown(self):
        self.db.close()

    def test_unknown_not_promoted_to_peer(self):
        self.assertEqual(self.db.execute("SELECT relation FROM edges WHERE u=4134 AND v=13335").fetchone()[0],"unknown")

    def test_conflict_preserved(self):
        self.assertEqual(self.db.execute("SELECT relation FROM edges WHERE u=4134 AND v=4837").fetchone()[0],"conflict")

    def test_roles_direction(self):
        self.assertEqual(self.db.execute("SELECT providers FROM nodes WHERE asn=174").fetchone()[0],1)
        self.assertEqual(self.db.execute("SELECT customers FROM nodes WHERE asn=3356").fetchone()[0],1)

    def test_isolate_retained(self):
        self.assertEqual(self.report["isolates"],1)
        self.assertEqual(self.report["connected_components"],2)

    def test_hop_boundary(self):
        d=neighborhood(self.db,"ipv4",174,1,100)
        self.assertEqual({n['asn'] for n in d['nodes']},{174,3356,4134})
        self.assertEqual(d['boundary_edges_not_drawn'],2)

    def test_two_hops(self):
        d=neighborhood(self.db,"ipv4",174,2,100)
        self.assertEqual(len(d['nodes']),5)

    def test_display_cap_and_stability(self):
        d=neighborhood(self.db,"ipv4",4134,1,2)
        self.assertTrue(d['truncated'])
        self.assertEqual(len(d['nodes']),2)
        self.assertEqual(d,neighborhood(self.db,"ipv4",4134,1,2))

    def test_observed_filter(self):
        d=neighborhood(self.db,"ipv4",4134,1,100,"observed")
        self.assertEqual({n['asn'] for n in d['nodes']},{4134,13335})

    def test_missing_node(self):
        with self.assertRaises(LookupError):
            neighborhood(self.db,"ipv4",12345)

    def test_layer_separation(self):
        with self.assertRaises(LookupError):
            neighborhood(self.db,"ipv6",174)

    def test_invalid_inputs(self):
        for kwargs in ({"limit":500},{"hops":3},{"evidence":"garbage"}):
            with self.assertRaises(ValueError):
                neighborhood(self.db,"ipv4",174,**kwargs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
