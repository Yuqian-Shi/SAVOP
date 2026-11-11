# AS topology preparation tools

These tools fetch public source snapshots, build provenance-aware AS maps,
sample bounded experiment topologies and compile routing-policy configurations.
Downloaded datasets and generated databases are not part of the source release.

## 🔧 Environment

```bash
python3 -m venv .venv-topology
.venv-topology/bin/python -m pip install -r lab/topology/requirements.txt
.venv-topology/bin/python -m unittest discover -s lab/topology -p 'test_*.py'
.venv-topology/bin/python lab/topology/fetch_sources.py --help
.venv-topology/bin/python lab/topology/build_map.py --help
.venv-topology/bin/python lab/topology/sample_topologies.py --help
.venv-topology/bin/python lab/topology/compile_scene.py --help
```

## 📚 Inputs and interpretation

`sources.json`, `policy_sources.json`, `sampling_design.json` and
`motif_design.json` record source and sampling choices. Preserve retrieved
metadata and hashes. Review provider terms before redistributing data; see
[third-party notices](../../THIRD_PARTY_NOTICES.md).

CAIDA relationships are inferred and RIS snapshots are collector observations.
Unknown relationships must remain unknown unless separately justified. A map,
connected sample or generated 1000-AS configuration is not evidence that a
1000-AS experiment ran, nor is an observed origin a source-address authorization.
