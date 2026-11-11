"""Fetch frozen public inputs without credentials; never overwrite an existing file.

Metadata records receipt time, final URL, headers and SHA-256. An existing input
is reused only when its recorded hash still matches. Partial downloads remain
under a unique .partial name for inspection (not silently reused).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(source, root):
    target_dir = root / source["id"]
    target_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".bz2" if source["url"].endswith(".bz2") else ".gz" if source["url"].endswith(".gz") else ".txt" if source["url"].endswith(".txt") else ".html"
    target = target_dir / ("input" + suffix)
    metadata = target_dir / "source.json"
    if metadata.exists():
        record = json.loads(metadata.read_text(encoding="utf-8"))
        if record["url"] != source["url"] or sha256(target) != record["sha256"]:
            raise ValueError(f"Input provenance/hash mismatch: {target}")
        print(f"Verified cached {source['id']}", flush=True)
        return record
    if target.exists():
        raise FileExistsError(f"Unmanifested input: {target}")
    partial = target.with_name(target.name + f".{time.time_ns()}.partial")
    req = Request(source["url"], headers={"User-Agent": "K5-AS-Topology/0.1 research-data-import"})
    count = 0
    digest = hashlib.sha256()
    print(f"Downloading {source['id']}", flush=True)
    with urlopen(req, timeout=90) as response, partial.open("xb") as f:
        if response.status != 200:
            raise ValueError(f"Unexpected HTTP status: {response.status}")
        headers = dict(response.headers)
        final_url = response.url
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            f.write(chunk)
            digest.update(chunk)
            count += len(chunk)
        f.flush()
        os.fsync(f.fileno())
        length = response.headers.get("Content-Length")
        if length is not None and count != int(length):
            raise ValueError(f"Truncated download {count} != {length}")
    # Antivirus/synchronization may briefly hold a just-closed large download.
    for attempt in range(20):
        try:
            partial.rename(target)
            break
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.5)
    record = dict(source, file=target.name, bytes=count, sha256=digest.hexdigest(),
                  retrieved_utc=datetime.now(timezone.utc).isoformat(), final_url=final_url,
                  response_headers=headers)
    with metadata.open("x", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    print(f"Saved {source['id']}: {count:,} bytes {record['sha256']}", flush=True)
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, default=Path(__file__).with_name("sources.json"))
    ap.add_argument("--raw", type=Path, required=True)
    args = ap.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    args.raw.mkdir(parents=True, exist_ok=True)
    for source in config["sources"]:
        fetch(source, args.raw)


if __name__ == "__main__":
    main()
