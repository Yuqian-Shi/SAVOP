"""Fresh-deployment CLI/API experiment; leaves the public runner unchanged."""
import argparse
import json
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace

import psutil
from coldstart_engine import DockerAPI
from process_memory import snapshot
from run_capacity import SafetyStop
from run_capacity_benchmark import TimedLab
from run_five_as import LABEL, dump, sha
from verify_capacity import check_run


class ColdLab(TimedLab):
    def __init__(self, args):
        super().__init__(args)
        self.api_records, self.creation_records, self.configurations = [], [], {}
        self.engine = DockerAPI(self.api_records)
        self.injected = False
        self.report['creation_backend'] = args.backend

    def command(self, argv, **kwargs):
        values = list(map(str, argv))
        if values[:3] == ['docker', 'run', '-d']:
            row = dict(argv=values, backend=self.args.backend, started=time.time(), start=time.monotonic())
            try:
                if self.args.backend == 'api':
                    fault = self.args.fault if not self.injected else None
                    self.injected = bool(fault) or self.injected
                    cid = self.engine.run(values, kwargs.get('timeout', 45), inject=fault)
                    result = SimpleNamespace(stdout=cid+'\n', stderr='', returncode=0)
                else:
                    result = super().command(argv, **kwargs)
                row.update(id=result.stdout.strip(), ok=True)
                return result
            except Exception as error:
                row.update(error=repr(error), ok=False)
                raise
            finally:
                row['seconds'] = time.monotonic() - row['start']
                self.creation_records.append(row)
        return super().command(argv, **kwargs)

    def owned(self, node):
        state = super().owned(node)
        if self.phase == 'create_containers':
            self.configurations[str(node)] = state
        return state


def collect_system(lab, stop):
    daemons = [p for p in psutil.process_iter(['name']) if p.info['name'] in ('dockerd', 'containerd')]
    with (lab.run/'system-samples.jsonl').open('x') as stream:
        while not stop.is_set():
            try:
                row = dict(time=time.time(), phase=lab.phase, cpu_times=psutil.cpu_times()._asdict(),
                           disks={k:v._asdict() for k,v in psutil.disk_io_counters(perdisk=True).items()},
                           io_pressure=Path('/proc/pressure/io').read_text(),
                           daemons={p.name():dict(pid=p.pid,cpu=p.cpu_times()._asdict(),io=p.io_counters()._asdict()) for p in daemons})
                stream.write(json.dumps(row)+'\n')
                stream.flush()
            except Exception as error:
                stream.write(json.dumps(dict(error=repr(error),time=time.time()))+'\n')
            stop.wait(1)


def worker(args):
    lab = ColdLab(args)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    stop = threading.Event()
    monitor = threading.Thread(target=collect_system, args=(lab,stop),daemon=True)
    with (lab.run/'docker-events.jsonl').open('x') as event_log:
        event_process = subprocess.Popen(['docker','events','--filter','type=container','--filter','event=create',
                                         '--filter','event=start','--filter',f'label={LABEL}={args.run_id}',
                                         '--format','{{json .}}'],stdout=event_log,stderr=subprocess.STDOUT)
        monitor.start()
        time.sleep(.5)  # Outside measured region; allow subscription to start.
        if event_process.poll() is not None:
            raise RuntimeError('Docker event listener did not start')
        start, cpu = time.monotonic(), time.process_time()
        try:
            lab.prepare()
            lab.qualify()
        except SafetyStop as error:
            lab.report.update(status='stopped_safety_reserve', error=str(error))
        except KeyboardInterrupt:
            lab.report.update(status='operator_interrupted')
        except Exception as error:
            expected = (isinstance(error, TimeoutError) and args.fault and lab.injected
                        and str(error) == 'Injected post-' + args.fault.removeprefix('after-') + ' response loss')
            lab.report.update(status='expected_fault' if expected else 'failed', error=traceback.format_exc())
        finally:
            lab.report['created_nodes'] = len(lab.nodes)
            try:
                lab.cleanup()
            except Exception:
                lab.report.update(status='failed_cleanup_exception',cleanup_exception=traceback.format_exc())
            with lab.timing('result_write','result.json'):
                dump(lab.run/'result.json',lab.report)
            end, cpu_elapsed = time.monotonic(), time.process_time()-cpu
            stop.set()
            monitor.join(timeout=5)
            event_process.terminate()
            event_process.wait(timeout=10)
            lab.engine.close()
    dump(lab.run/'api-requests.json',lab.api_records)
    dump(lab.run/'creation-commands.json',lab.creation_records)
    dump(lab.run/'created-configs.json',lab.configurations)
    perf = dict(run=args.run_id, backend=args.backend, AS=args.as_count,wall_seconds=end-start,
                start=start-lab.zero,end=end-lab.zero,harness_cpu_seconds=cpu_elapsed,
                harness_memory=snapshot(), events=lab.events,status=lab.report['status'],
                source_sha256={p.name:sha(p) for p in Path(__file__).parent.glob('*.py')},
                boundary='prepare through result close, including hold and cleanup; diagnostic exports excluded')
    dump(lab.run/'performance.json',perf)
    remaining = subprocess.check_output(['docker','ps','-aq','--filter',f'label={LABEL}={args.run_id}'],text=True).strip()
    assert not remaining and not lab.report['cleanup_errors'] and lab.report['host_unchanged']
    if args.fault:
        assert lab.report['status']=='expected_fault' and len(lab.nodes)==1
        print(json.dumps(dict(fault=args.fault,passed=True,remaining=0)),flush=True)
        return 0
    print(json.dumps(dict(run=args.run_id,status=lab.report['status'],wall=end-start)),flush=True)
    return int(lab.report['status']!='passed_capacity_tier')


def schedule(stage):
    rng = random.Random(2026102102)
    rows = []
    for count, blocks in ([(1,1)] if stage=='cold-smoke' else [(30,3)]):
        first = ['cli','api']
        rng.shuffle(first)
        for block in range(1,blocks+1):
            for backend in first if block%2 else list(reversed(first)):
                rows.append(dict(run=f'cap-d{count:02d}-{backend}{block}',AS=count,block=block,backend=backend))
    return rows


def batch(args):
    root,build = args.root.resolve(strict=True),args.build.resolve(strict=True)
    if root.parent!=Path('/mnt/hdd') or not root.name.startswith('k5-capacity-opt-cold-'):
        raise ValueError('Fresh data-volume experiment root required')
    if args.stage=='cold-confirm':
        # No 300-node measurement before both smoke conditions and config equivalence pass.
        gate=json.loads((root/'cold-smoke-analysis.json').read_text())
        assert gate['passed'] and gate['configurations_equal']
    plan=dict(stage=args.stage,seed=2026102102,schedule=schedule(args.stage),
              source_sha256={p.name:sha(p) for p in root.glob('*.py')},
              fixed=['fresh containers every run','one create worker','compact evidence','pinned Agent BIRD image',
                     'unchanged topology and functional gates','60-second steady observation','8 other workers'],
              unit='same-VM technical repetition, not independent hardware replication',
              cold_definition='fresh process, containers and namespaces; preinstalled image/build, OS cache not flushed',
              change='only docker run transport: CLI vs local Unix-socket API create/start; inspect/wiring unchanged',
              decision='do not change public default in this trial; candidate promising only if all three 300-node pairs faster and aggregate complete wall reduction >=5%',
              stop='any functional/resource/cleanup/config-equivalence/source failure; no selective repeats')
    dump(root/(args.stage+'-plan.json'),plan)
    for rel in ('Cargo.toml','savop.toml','router/bird','router/birdc','router/birdcl','target/release/sav_agent','target/release/sav_lab_gen'):
        target=root/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():
            assert sha(target)==sha(build/rel)
        else:
            shutil.copy2(build/rel,target)
    rows=[]
    for entry in plan['schedule']:
        assert not subprocess.check_output(['docker','ps','-q'],text=True).strip(), 'Other containers are running'
        assert psutil.virtual_memory().available > 6*1024**3
        cmd=[sys.executable,'-B',str(Path(__file__)),'--worker','--root',str(root),'--build',str(build),
             '--run-id',entry['run'],'--as-count',str(entry['AS']),'--backend',entry['backend']]
        with (root/(entry['run']+'-console.log')).open('x') as stream:
            result=subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT)
        row=dict(**entry,returncode=result.returncode)
        if result.returncode==0:
            row['audit']=check_run(root/entry['run'])
            row['wall']=json.loads((root/entry['run']/'performance.json').read_text())['wall_seconds']
        dump(root/(entry['run']+'-audit.json'),row)
        print(json.dumps(row),flush=True)
        if result.returncode or not row['audit']['qualified']:
            return 1
        rows.append(row)
    dump(root/(args.stage+'-results.json'),rows)
    return 0


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--stage',choices=('cold-smoke','cold-confirm'),default='cold-smoke')
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--run-id')
    parser.add_argument('--as-count',type=int)
    parser.add_argument('--backend',choices=('cli','api'),default='cli')
    parser.add_argument('--fault',choices=('after-create','after-start'))
    args=parser.parse_args()
    args.family,args.hold,args.create_workers,args.evidence_encoding=4,60,1,'compact'
    if os.geteuid()!=0:
        raise SystemExit('Linux root required')
    raise SystemExit(worker(args) if args.worker else batch(args))
