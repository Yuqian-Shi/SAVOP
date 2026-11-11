"""Copy regular experiment evidence, excluding live sockets; never delete sources."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys


def main(root, output):
    root = root.resolve(strict=True)
    output = output.absolute()
    if root.parent != Path("/mnt/hdd") or not root.name.startswith("k5-five-as-"):
        raise ValueError("Expected dedicated data-disk laboratory")
    if output.parent != root or output.exists() or not output.name.startswith("evidence-export-"):
        raise ValueError("Fresh direct-child evidence export required")
    runs = sorted(p for p in root.iterdir() if p.is_dir() and (p / "result.json").is_file())
    if not runs:
        raise ValueError("No completed records")
    output.mkdir()
    copied, excluded = {}, []

    def copy(source, target):
        mode = source.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(f"Refuse symlink: {source}")
        if stat.S_ISDIR(mode):
            target.mkdir(parents=True, exist_ok=True)
            for child in sorted(source.iterdir()):
                copy(child, target / child.name)
        elif stat.S_ISREG(mode):
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise FileExistsError(target)
            shutil.copy2(source, target)
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            assert hashlib.sha256(target.read_bytes()).hexdigest() == source_sha
            copied[str(target.relative_to(output))] = source_sha
        else:
            excluded.append({"path": str(source.relative_to(root)), "file_mode": stat.filemode(mode)})

    for run in runs:
        copy(run, output / run.name)
        generated = root / ("savop_run_" + run.name)
        if generated.is_dir():
            copy(generated, output / "generated" / generated.name)
    for source in sorted(root.iterdir()):
        if source.is_file() and (source.suffix in (".py", ".json", ".log", ".sh") or source.name in ("Cargo.toml", "Cargo.lock", "savop.toml")):
            copy(source, output / "support" / source.name)
    for rel in ("agent/src", "agent/tests", "agent/Cargo.toml", "target/release/sav_agent",
                "target/release/sav_lab_gen", "router/bird", "router/birdc", "router/birdcl"):
        source = root / rel
        if source.exists():
            copy(source, output / "build" / rel)
    environment = {"python": sys.version, "observation_time": "at export, after selected runs", "tools": []}
    for command in (["cargo", "--version"], ["rustc", "--version"], ["docker", "--version"],
                    ["nft", "--version"], ["uname", "-r"]):
        result = subprocess.run(command, text=True, capture_output=True, timeout=10)
        environment["tools"].append({"command": command, "returncode": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr})
    manifest = {"status": "exported_regular_files", "source_root": str(root), "export_environment": environment,
                "runs": [r.name for r in runs], "artifacts_sha256": copied, "excluded_special_files": excluded}
    with (output / "export-manifest.json").open("x") as handle:
        json.dump(manifest, handle, indent=2)
    print(json.dumps({"runs": manifest["runs"], "files": len(copied), "excluded_special_files": len(excluded)}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    main(a.root, a.output)
