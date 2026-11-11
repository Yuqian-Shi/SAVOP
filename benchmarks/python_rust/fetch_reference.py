"""Fetch only the pinned upstream Python reference files, with SHA-256 checks."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


def fetch(destination):
    lock_path = Path(__file__).with_name("reference-lock.json")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    revision = lock["revision"]
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError("Expected a full immutable Git commit")
    base = "https://raw.githubusercontent.com/NASP-THU/SAV-Open-Playground/" + revision
    destination = Path(destination).absolute()
    if destination.is_symlink():
        raise ValueError("Reference destination must not be a symbolic link")
    planned = []
    for relative, expected in lock["files"].items():
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError("Unsafe reference path")
        target = destination / rel
        if target.is_symlink():
            raise ValueError("Reference file must not be a symbolic link")
        if target.exists():
            content = target.read_bytes()
        else:
            with urllib.request.urlopen(base + "/" + rel.as_posix(), timeout=60) as response:
                content = response.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError(f"Reference hash mismatch: {relative}")
        planned.append((target, content))
    for target, content in planned:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(content)
    print(json.dumps({"revision": revision, "verified_files": len(planned)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    fetch(parser.parse_args().destination)
