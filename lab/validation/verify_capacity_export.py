"""Portable, streaming hash and inventory verification of a capacity export."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def main(args):
    root = args.root.resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["files"].items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe manifest path")
        raw = root / Path(*relative.parts)
        path = raw.resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file() or raw.is_symlink():
            raise ValueError("Unexpected exported object")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("Hash mismatch: " + name)
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    assert actual_files == set(manifest["files"]) | {"manifest.json"}
    report = {"passed": True, "regular_files_verified": len(manifest["files"]),
              "excluded_special_objects": len(manifest["excluded_special"]),
              "agent_sha256": manifest["files"]["target/release/sav_agent"]}
    assert report["agent_sha256"] == "fd0754383770facba20fee275144167970cf73746aa06921177044d78e9baf79"
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args())
