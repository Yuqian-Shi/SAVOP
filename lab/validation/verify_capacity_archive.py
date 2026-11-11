"""Verify every regular tar member without extracting the large evidence tree."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main(args):
    archive_hash = digest(args.archive)
    if archive_hash != args.expected_sha256.lower():
        raise ValueError("Archive differs from the remote completed package")
    actual, manifest = {}, None
    with tarfile.open(args.archive, "r|gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "evidence-export":
                raise ValueError("Unsafe archive name")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("Unexpected special object in archive")
            name = PurePosixPath(*path.parts[1:]).as_posix()
            if name in actual:
                raise ValueError("Duplicate archive member")
            stream = archive.extractfile(member)
            if name == "manifest.json":
                raw = stream.read()
                manifest = json.loads(raw)
                actual[name] = hashlib.sha256(raw).hexdigest()
            else:
                actual[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if manifest is None:
        raise ValueError("Missing manifest")
    assert set(actual) == set(manifest["files"]) | {"manifest.json"}
    assert all(actual[name] == expected for name, expected in manifest["files"].items())
    assert manifest["files"]["target/release/sav_agent"] == "fd0754383770facba20fee275144167970cf73746aa06921177044d78e9baf79"
    sidecars = []
    for name in ("summary.json", "summary.csv", "audit-final.json", "validation-tests.log",
                 "final-health.log", "preflight-classification.json", "fallback-plan.json"):
        path = args.archive.parent / name
        if path.exists():
            assert digest(path) == manifest["files"][name]
            sidecars.append(name)
    result = {"passed": True, "archive_sha256": archive_hash,
              "regular_files_verified": len(manifest["files"]),
              "excluded_special_objects": len(manifest["excluded_special"]),
              "sidecars_verified": sidecars,
              "verifier_sha256": digest(Path(__file__)),
              "method": "Streaming decompression and SHA256 of all regular members; no extraction"}
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2)
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args())
