"""Inject one post-create CLI timeout, then verify bounded owned cleanup.

Only fresh capacity-opt roots and a fixed new run ID are accepted. This fault
test creates isolated sleeping containers, never starts the routing workload.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

from run_capacity import CapacityLab
from run_five_as import LABEL, dump


class FaultLab(CapacityLab):
    injected = False
    def command(self, argv, **kwargs):
        result = super().command(argv, **kwargs)
        values = list(map(str,argv))
        if (values[:3] == ['docker','run','-d'] and
                f'k5-{self.args.run_id}-n3' in values and not self.injected):
            self.injected = True
            self.report['injected_created_id'] = result.stdout.strip()
            raise subprocess.TimeoutExpired(values,45)
        return result


def main(args):
    if os.geteuid()!=0:
        raise RuntimeError('Linux root required')
    args.root=args.root.resolve(strict=True)
    if args.root.parent!=Path('/mnt/hdd') or not args.root.name.startswith('k5-capacity-opt-'):
        raise ValueError('Use a fresh capacity optimization directory')
    if not hasattr(CapacityLab,'create_node'):
        raise RuntimeError('Concurrent creation implementation is not installed')
    if subprocess.check_output(['docker','ps','-q'],text=True).strip():
        raise RuntimeError('Other containers are running')
    args.run_id='cap-fault-w4'
    args.as_count,args.family,args.hold,args.create_workers=1,4,60,4
    args.evidence_encoding='compact'
    lab=FaultLab(args)
    expected=False
    try:
        lab.prepare()
    except subprocess.TimeoutExpired:
        expected=lab.injected
        lab.report.update(status='expected_injected_creation_timeout')
    finally:
        lab.report['created_nodes']=len(lab.nodes)
        lab.report['injected_id_registered']=lab.report.get('injected_created_id') in {r['id'] for r in lab.nodes.values()}
        lab.cleanup()
        dump(lab.run/'result.json',lab.report)
    remaining=subprocess.check_output(['docker','ps','-aq','--filter',f'label={LABEL}={args.run_id}'],text=True).strip()
    assert expected and lab.report['injected_id_registered']
    assert lab.report['status']=='expected_injected_creation_timeout'
    assert not lab.report['cleanup_errors'] and lab.report['host_unchanged'] and not remaining
    assert 'deployment_seconds' not in lab.report['phase_times']
    audit=dict(passed=True,created_nodes=len(lab.nodes),injected_id_registered=True,
               remaining_owned_containers=0,host_unchanged=True,
               scope='post-create timeout recovery plus started-task join and owned cleanup; no workload or performance claim')
    dump(args.root/'creation-failure-audit.json',audit)
    print(json.dumps(audit))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    main(parser.parse_args())
