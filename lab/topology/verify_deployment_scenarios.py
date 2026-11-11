"""Independent validation of explicit deployment plans, not a runtime test."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify(root, previous, samples):
    groups = sorted(p for p in root.iterdir() if p.is_dir())
    assert len(groups) == 12
    rows = []
    for group in groups:
        manifest = load(group / "manifest.json")
        assert manifest["input_topology_sha256"] == sha(samples / group.name / "topology.json")
        for name, value in manifest["artifacts"].items():
            assert sha(group / name) == value
        for name, value in manifest["code_artifacts"].items():
            assert sha(group / "code" / name) == value
        assert sha(group / "code/compile_scene.py") == manifest["compiler_sha256"]
        for name in ("savop-base.json", "savop-anycast.json"):
            assert sha(group / name) == sha(previous / group.name / name), name
        base = load(group / "savop-base.json")
        matrix = load(group / "scenario-matrix.json")
        adjacency = {n: set() for n in base["devices"]}
        for a, b, _ in base["links"]:
            adjacency[a].add("eth_" + b)
            adjacency[b].add("eth_" + a)
        assert matrix["deployment_contract"]["default"] == "no installed SAV anywhere"
        assert matrix["deployment_contract"]["data_plane_auto"] is False
        assert matrix["deployment_contract"]["address_family"] == base["auto_ip_version"]
        for case in matrix["cases"]:
            arms = case["deployment_arms"]
            assert len(arms) == 3
            assert arms[0]["mechanism"] is None and arms[0]["targets"] == []
            assert arms[0]["deployment_fraction"] == 0
            expected = ({case["victim"]["node_id"]} if case["mode"] == "unicast" else
                        {n["node_id"] for n in case["provider_nodes" if case["mode"] == "multihoming" else "origin_nodes"]})
            assert {a["mechanism"] for a in arms[1:]} == {"strict_urpf", "loose_urpf"}
            for arm in arms[1:]:
                assert {t["node_id"] for t in arm["targets"]} == expected
                assert len(arm["targets"]) == len(expected)
                assert arm["deployment_fraction"] == len(expected) / len(base["devices"])
                for target in arm["targets"]:
                    node = target["node_id"]
                    assert target["lab_asn"] == base["devices"][node]["as"]
                    assert set(target["ingress_interfaces"]) == adjacency[node]
        rows.append({"group": group.name, "nodes": len(base["devices"]),
                     "cases": len(matrix["cases"]), "deployment_arms": sum(len(c["deployment_arms"]) for c in matrix["cases"]),
                     "previous_generator_inputs_identical": True})
    return {"status": "passed_offline_deployment_plan_audit", "groups": rows,
            "runtime_status": "not_run_at_100_or_1000_AS"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "previous", "samples", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    result = verify(a.root, a.previous, a.samples)
    with a.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False))
