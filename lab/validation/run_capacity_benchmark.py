"""Paired full-workflow benchmark; fixed functional gates and owned cleanup.

Each observation is a fresh subprocess/deployment, with raw evidence retained.
Stages run separately so encoding and deployment concurrency have distinct
concurrent controls. No population confidence interval from one-VM repeats.
"""
import argparse
from contextlib import contextmanager
import functools
import json
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import time
import traceback

from run_capacity import CapacityLab, SafetyStop
from run_five_as import dump, sha
from verify_capacity import check_run
from process_memory import snapshot as memory_snapshot


class TimedLab(CapacityLab):
    def __init__(self, args):
        self.zero, self.events = time.monotonic(), []
        super().__init__(args)

    def __setattr__(self, name, value):
        if name == 'phase' and hasattr(self, 'events'):
            self.events.append(dict(kind='phase', label=value, start=time.monotonic()-self.zero))
        super().__setattr__(name, value)

    @contextmanager
    def timing(self, kind, label):
        start, cpu = time.monotonic(), time.thread_time()
        ok = False
        try:
            yield
            ok = True
        finally:
            end = time.monotonic()
            self.events.append(dict(kind=kind, label=label, start=start-self.zero, end=end-self.zero,
                                    seconds=end-start, thread_cpu_seconds=time.thread_time()-cpu, ok=ok))


def timed(name):
    original = getattr(CapacityLab, name)
    @functools.wraps(original)
    def method(self, *args, **kwargs):
        label = str(args[0]) if args else name
        with self.timing(name, label):
            return original(self, *args, **kwargs)
    setattr(TimedLab, name, method)


for name in ('prepare', 'qualify', 'cleanup', 'observe', 'write_observation', 'wait_ready', 'traffic'):
    timed(name)


def worker(args):
    lab = TimedLab(args)
    def stop(signum, frame):
        raise KeyboardInterrupt('termination requested')
    signal.signal(signal.SIGTERM, stop)
    start, cpu = time.monotonic(), time.process_time()
    try:
        lab.prepare()
        lab.qualify()
    except SafetyStop as exc:
        lab.report.update(status='stopped_safety_reserve', error=str(exc))
    except KeyboardInterrupt:
        lab.report.update(status='operator_interrupted')
    except Exception:
        lab.report.update(status='failed', error=traceback.format_exc())
    finally:
        lab.report['created_nodes'] = len(lab.nodes)
        try:
            lab.cleanup()
        except Exception:
            lab.report.update(status='failed_cleanup_exception', cleanup_exception=traceback.format_exc())
        with lab.timing('result_write', 'result.json'):
            dump(lab.run/'result.json', lab.report)
        end, process_cpu = time.monotonic(), time.process_time()-cpu
    # Read after the timed region. getrusage can retain the launcher's pre-exec
    # high-water mark, so keep it only as a separately labelled diagnostic.
    memory = memory_snapshot()
    perf = dict(run=args.run_id, encoding=args.evidence_encoding,
                create_workers=args.create_workers, AS=args.as_count,
                wall_seconds=end-start, start=start-lab.zero, end=end-lab.zero,
                harness_cpu_seconds=process_cpu,
                harness_peak_rss_mib=memory['post_exec_peak_rss_mib'],
                harness_memory=memory,
                events=lab.events, status=lab.report['status'],
                boundary='before prepare to result.json close, includes 60s hold and cleanup; excludes imports, constructor and performance export',
                source_sha256={p.name:sha(p) for p in Path(__file__).parent.glob('*.py')})
    dump(lab.run/'performance.json', perf)
    print(json.dumps({k:perf[k] for k in ('run','status','wall_seconds','harness_peak_rss_mib')}), flush=True)
    return int(lab.report['status'] != 'passed_capacity_tier')


def schedule(stage, selected_workers):
    rng, rows = random.Random(20261021), []
    if stage == 'encoding':
        for count, blocks in ((1, 1), (5, 1), (30, 3)):
            first = rng.choice([['pretty','compact'], ['compact','pretty']])
            for block in range(1, blocks+1):
                for encoding in first if block % 2 else list(reversed(first)):
                    rows.append(dict(run=f'cap-e{count:02d}-{encoding[0]}{block}', AS=count, block=block,
                                     encoding=encoding, create_workers=1))
    elif stage == 'concurrency-screen':
        order = [1, 2, 4, 8]
        rng.shuffle(order)
        for workers in order:
            rows.append(dict(run=f'cap-s05-w{workers}', AS=5, block=1,
                             encoding='compact', create_workers=workers))
    else:
        if selected_workers not in (2, 4, 8):
            raise ValueError('Select a screened concurrency level')
        first = [1, selected_workers]
        rng.shuffle(first)
        for block in range(1, 4):
            for workers in first if block % 2 else list(reversed(first)):
                rows.append(dict(run=f'cap-c30-w{workers}b{block}', AS=30, block=block,
                                 encoding='compact', create_workers=workers))
    return rows


def batch(args):
    root, build = args.root.resolve(strict=True), args.build.resolve(strict=True)
    if root.parent != Path('/mnt/hdd') or not root.name.startswith('k5-capacity-opt-'):
        raise ValueError('Use a fresh /mnt/hdd/k5-capacity-opt-* root')
    if args.stage != 'encoding' and '--create-workers' not in (Path(__file__).parent/'run_capacity.py').read_text():
        raise RuntimeError('Concurrency implementation not installed')
    source = Path(__file__).parent
    plan = dict(stage=args.stage, seed=20261021, schedule=schedule(args.stage,args.selected_workers),
                hold=60, family=4, unit='one fresh deployment/process on one VM, technical repeats',
                pairing='within AS and block; randomized first order, alternated subsequent blocks',
                fixed=['Agent and BIRD binaries', 'image digest', 'topology', '8 observation/start/cleanup workers',
                       '1s auto interval', '2s command timeout', 'all-node checks', '3s stability', '60s hold', '4 UDP rounds'],
                timing='prepare to final result close, excluding benchmark export; nested events not additive',
                gates='unchanged capacity verifier; stop on ANY failure; keep all runs',
                comparison='encoding: pretty vs compact with one creation worker; concurrency: compact both sides',
                selector='screen: smallest worker count within 10% of fastest complete wall time among passed runs; confirm independently',
                source_sha256={p.name:sha(p) for p in source.glob('*.py')})
    dump(root/(args.stage+'-plan.json'), plan)
    # Copy identical build inputs before all measured runs, avoiding first-run-only copy cost.
    for relative in ('Cargo.toml','savop.toml','router/bird','router/birdc','router/birdcl',
                     'target/release/sav_agent','target/release/sav_lab_gen'):
        target = root/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if sha(target) != sha(build/relative):
                raise RuntimeError('Different build in benchmark root')
        else:
            shutil.copy2(build/relative, target)
    rows = []
    for entry in plan['schedule']:
        if subprocess.check_output(['docker','ps','-q'],text=True).strip():
            raise RuntimeError('Other containers are running; do not interfere')
        command = [sys.executable,'-B',str(Path(__file__)), '--worker','--root',str(root),'--build',str(build),
                   '--run-id',entry['run'],'--as-count',str(entry['AS']), '--evidence-encoding',entry['encoding'],
                   '--create-workers',str(entry['create_workers'])]
        with (root/(entry['run']+'-console.log')).open('x') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        row = dict(**entry, returncode=result.returncode)
        if result.returncode == 0:
            row['audit'] = check_run(root/entry['run'])
            row['performance'] = json.loads((root/entry['run']/'performance.json').read_text())
        dump(root/(entry['run']+'-audit.json'), row)
        rows.append(row)
        print(json.dumps({k:v for k,v in row.items() if k not in ('audit','performance')} |
                         {'wall_seconds':row.get('performance',{}).get('wall_seconds')}), flush=True)
        if result.returncode or not row['audit']['qualified']:
            return 1
    dump(root/(args.stage+'-results.json'), rows)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--stage',choices=('encoding','concurrency-screen','concurrency-confirm'),default='encoding')
    parser.add_argument('--selected-workers',type=int)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--run-id')
    parser.add_argument('--as-count',type=int)
    parser.add_argument('--evidence-encoding',choices=('pretty','compact'),default='compact')
    parser.add_argument('--create-workers',type=int,choices=(1,2,4,8),default=1)
    parser.add_argument('--family',type=int,default=4,choices=(4,))
    parser.add_argument('--hold',type=int,default=60,choices=(60,))
    options = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Requires Linux root on dedicated development VM')
    raise SystemExit(worker(options) if options.worker else batch(options))
