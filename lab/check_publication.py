"""Check the candidate source tree; findings never print matched secret values."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SKIP = {'.git', 'target', '.venv', '.venv-bench', '.venv-topology', '__pycache__', '.cache'}
BLOCKED_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.crt', '.sqlite', '.gz', '.bz2', '.tar', '.zip'}
SECRET_PATTERNS = [
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{25,}\b'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{30,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'(?i)(?:api_key|access_token|admin_token|password)\s*[:=]\s*[\x22\x27](?!CHANGE_ME|EXAMPLE|example|test|dummy)[^\x22\x27\n]{8,}[\x22\x27]'),
]
PRIVATE_PATTERNS = (
    re.compile(r'\bdev-u\d+\b'),
    re.compile(r'/opt/Work/\d+'),
    re.compile(r'[A-Z]:[\\/](?:Work|Users)[\\/]'),
)


def files(root):
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], capture_output=True)
    if result.returncode == 0 and result.stdout:
        return [root / name.decode('utf-8') for name in result.stdout.split(b'\0') if name]
    paths = []
    for current, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP]
        paths.extend(Path(current) / name for name in names)
    return sorted(paths)


def check(root):
    findings, inventory = [], []
    for path in files(root):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or path.is_symlink():
            findings.append({'path': rel, 'kind': 'missing or symlink'})
            continue
        if (any(p in {'.git', 'target', 'savop_demo'} for p in path.relative_to(root).parts)
                or rel.startswith('lab/data/topologies/') or path.suffix in BLOCKED_SUFFIXES
                or path.name.startswith('.env') and path.name != '.env.example'):
            findings.append({'path': rel, 'kind': 'excluded artifact'})
        raw = path.read_bytes()
        inventory.append({'path': rel, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        if len(raw) > 5 * 1024 * 1024:
            findings.append({'path': rel, 'kind': 'large file requires review'})
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            continue  # Original router documentation assets may be non-UTF8.
        for number, line in enumerate(text.splitlines(), 1):
            if any(pattern.search(line) for pattern in PRIVATE_PATTERNS):
                findings.append({'path': rel, 'line': number, 'kind': 'private machine/path marker'})
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                findings.append({'path': rel, 'line': number, 'kind': 'possible credential'})
        if path.suffix == '.json':
            try:
                json.loads(text)
            except ValueError:
                findings.append({'path': rel, 'kind': 'invalid JSON'})
        if path.suffix == '.py':
            try:
                ast.parse(text)
            except SyntaxError:
                findings.append({'path': rel, 'kind': 'invalid Python'})
        if path.suffix == '.md' and (rel.startswith('docs/') or rel in ('README.md', 'THIRD_PARTY_NOTICES.md', 'benchmarks/python_rust/README.md')):
            for target in re.findall(r'\]\(([^)]+)\)', text):
                if target.startswith(('http:', 'https:', '#', 'mailto:')):
                    continue
                if not (path.parent / target.split('#', 1)[0]).exists():
                    findings.append({'path': rel, 'kind': 'broken relative link', 'target': target})
    required = ('LICENSES/MIT.txt', 'LICENSES/GPL-2.0.txt', 'LICENSES/LGPL-2.0.txt',
                'LICENSES/LGPL-2.1.txt', 'docs/support-matrix.md', 'docs/upstream.md')
    for rel in required:
        if not (root / rel).is_file():
            findings.append({'path': rel, 'kind': 'missing release file'})
    return {'passed': not findings, 'file_count': len(inventory),
            'total_bytes': sum(row['bytes'] for row in inventory),
            'findings': findings, 'files': inventory,
            'scope': 'candidate current tree only; pattern checks are not a guarantee that all sensitive material was detected'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.root.resolve(strict=True))
    with args.report.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps({key: report[key] for key in ('passed', 'file_count', 'total_bytes', 'findings')}))
    raise SystemExit(0 if report['passed'] else 1)
