"""Export regular capacity evidence files and SHA256 manifest, never sockets."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def main(args):
    root = args.root.resolve(strict=True)
    if root.parent != Path("/mnt/hdd") or not root.name.startswith("k5-capacity-"):
        raise ValueError("Unexpected capacity root")
    target = root / "evidence-export"
    target.mkdir(exist_ok=False)
    sources = [p for p in root.iterdir() if p != target and
               (p.is_file() or p.name.startswith(("cap-", "savop_run_")))]
    sources += [root / "router", root / "target/release"]
    files, excluded = {}, []
    for source in sources:
        candidates = source.rglob("*") if source.is_dir() else [source]
        for path in candidates:
            relative = path.relative_to(root)
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                excluded.append(str(relative))
            elif path.is_file():
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    raise ValueError("Duplicate export")
                shutil.copy2(path, destination)
                with path.open("rb") as stream:
                    files[str(relative)] = hashlib.file_digest(stream, "sha256").hexdigest()
    manifest = {"root": str(root), "files": files, "excluded_special": excluded}
    with (target / "manifest.json").open("x") as out:
        json.dump(manifest, out, indent=2)
    print(json.dumps({"export": str(target), "files": len(files), "excluded": len(excluded)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    main(parser.parse_args())
