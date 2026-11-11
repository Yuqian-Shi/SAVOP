"""Copy small benchmark artifacts and omit private host/source paths."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def export(source, output):
    source = source.resolve(strict=True)
    if output.exists():
        raise ValueError('Public export requires a fresh directory')
    manifest = json.loads((source / 'manifest.json').read_text())
    output.mkdir(parents=True, exist_ok=False)
    names = ('raw.jsonl', 'design.json', 'verification.json', 'summary.csv',
             'summary.json', 'analysis-provenance.json')
    for name in names:
        shutil.copyfile(source / name, output / name)
    environment = {key: manifest[key] for key in (
        'kernel', 'python', 'rustc', 'cargo', 'binary_sha256', 'affinity_available',
        'dependencies', 'inputs', 'design_sha256')}
    environment['reference_revision'] = json.loads(Path(__file__).with_name('reference-lock.json').read_text())['revision']
    environment['scope'] = 'same-VM component measurements; not whole-Agent or end-to-end timings'
    environment['omitted'] = ['hostname', 'absolute build/source/binary paths', 'absolute source-file map']
    environment['source_manifest_sha256'] = hashlib.sha256((source / 'manifest.json').read_bytes()).hexdigest()
    (output / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
    checksums = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(output.iterdir()) if path.is_file()}
    (output / 'SHA256SUMS.json').write_text(json.dumps(checksums, indent=2) + '\n')
    print(json.dumps({'files': len(checksums), 'raw_measurements': 504, 'scope': 'public component evidence subset'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='completed results directory')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    export(args.source, args.output)
