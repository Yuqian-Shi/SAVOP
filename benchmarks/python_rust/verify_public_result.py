"""Independently recompute the small public component-results table."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics


def verify(root):
    hashes = json.loads((root / 'SHA256SUMS.json').read_text())
    for name, expected in hashes.items():
        assert Path(name).name == name, 'Unsafe artifact name'
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
    raw = [json.loads(line) for line in (root / 'raw.jsonl').read_text().splitlines()]
    design = json.loads((root / 'design.json').read_text())
    assert len(raw) == 504 and len(design['schedule']) == 252
    groups = {}
    for index, row in enumerate(raw):
        pair, slot = divmod(index, 2)
        cell = design['schedule'][pair]
        assert row['pair_no'] == pair and row['language'] == cell['order'][slot]
        assert all(row[key] == cell[key] for key in ('app', 'family', 'mode', 'repeat', 'iterations'))
        count = cell['count']
        assert row['input_routes'] == count
        expected_count = count
        if cell['app'] == 'fp_urpf':
            expected_count *= 5 if cell['mode'] == 'update' and cell['iterations'] % 2 else 4
        assert row['count'] == expected_count
        key = (cell['app'], cell['family'], count, cell['mode'])
        groups.setdefault(key, {}).setdefault(cell['repeat'], {})[row['language']] = row
    comparisons = 0
    with (root / 'summary.csv').open(newline='') as stream:
        summary = list(csv.DictReader(stream))
    assert len(summary) == len(groups) == 36
    for entry in summary:
        key = (entry['app'], int(entry['family']), int(entry['count']), entry['mode'])
        repeats = groups[key]
        assert set(repeats) == set(range(7))
        ratios = [row['python']['elapsed_ns'] / row['rust']['elapsed_ns'] for row in repeats.values()]
        wanted = {'paired_speedup_median': statistics.median(ratios),
                  'paired_speedup_min': min(ratios), 'paired_speedup_max': max(ratios)}
        for language in ('python', 'rust'):
            rows = [row[language] for row in repeats.values()]
            core = [row['elapsed_ns'] / row['iterations'] / 1e6 for row in rows]
            wanted.update({
                language + '_core_ms': statistics.median(core),
                language + '_core_min_ms': min(core), language + '_core_max_ms': max(core),
                language + '_peak_rss_mib': statistics.median(row['peak_rss_kib'] / 1024 for row in rows),
                language + '_process_cpu_ms': statistics.median(row['process_cpu_seconds'] * 1000 for row in rows),
                language + '_process_wall_ms': statistics.median(row['process_wall_ns'] / 1e6 for row in rows),
            })
        for name, value in wanted.items():
            assert math.isclose(float(entry[name]), value, rel_tol=1e-10, abs_tol=1e-12), (key, name)
            comparisons += 1
    return {'passed': True, 'measurements': len(raw), 'cells': len(groups),
            'table_values_recomputed': comparisons, 'file_hashes_verified': len(hashes)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(verify(parser.parse_args().directory)))
