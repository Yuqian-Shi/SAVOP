"""Offline transport safety and no-retry checks; never opens a Docker socket."""
import copy
from pathlib import PurePosixPath
import time
import unittest
from unittest.mock import Mock

from coldstart_engine import DockerAPI, payload_from_run
from run_capacity import CapacityLab
import test_capacity_creation


def fixture_command():
    lab=test_capacity_creation.CreationTests().lab()
    lab.root=PurePosixPath('/mnt/hdd/k5-capacity-unit')
    lab.generated=lab.root/'savop_run_cap-unit-test'
    lab.report['image']='sha256:'+'a'*64
    lab.inspect=Mock(return_value=None)
    lab.command=Mock(side_effect=RuntimeError('capture only'))
    try:
        CapacityLab.create_node(lab,1)
    except RuntimeError:
        pass
    return list(map(str,lab.command.call_args.args[0]))


class EngineTests(unittest.TestCase):
    def test_exact_runtime_command_translates_safely(self):
        name,payload=payload_from_run(fixture_command())
        self.assertEqual(name,'k5-cap-unit-test-n1')
        host=payload['HostConfig']
        self.assertEqual(host['Memory'],512*1024**2)
        self.assertEqual(host['MemorySwap'],host['Memory'])
        self.assertEqual(host['NanoCpus'],10**9)
        self.assertEqual(host['PidsLimit'],128)
        self.assertEqual(host['NetworkMode'],'none')
        self.assertFalse(host['Privileged'])
        self.assertEqual(payload['Entrypoint'],['/bin/sleep'])

    def test_rejects_network_memory_name_label_mount_and_extra_flags(self):
        command=fixture_command()
        for flag,value in [('--network','host'),('--memory','1g'),('--name','someone-else'),
                           ('--label','org.savop.k5-validation=other'),
                           ('--mount','type=bind,source=/,target=/build,readonly')]:
            changed=copy.copy(command)
            changed[changed.index(flag)+1]=value
            with self.subTest(flag=flag),self.assertRaises(ValueError):
                payload_from_run(changed)
        with self.assertRaises(ValueError):
            payload_from_run(command[:3]+['--privileged','yes']+command[3:])

    def api(self):
        client=DockerAPI([])
        client.request=Mock(side_effect=[{'ApiVersion':'1.52','MinAPIVersion':'1.44'},{'Id':'a'*64},None])
        return client

    def test_create_then_start_full_id(self):
        client=self.api()
        self.assertEqual(client.run(fixture_command()),'a'*64)
        self.assertEqual(client.request.call_count,3)
        self.assertIn('/'+'a'*64+'/start',client.request.call_args.args[1])

    def test_fault_after_create_does_not_start_or_retry(self):
        client=self.api()
        with self.assertRaisesRegex(TimeoutError,'post-create'):
            client.run(fixture_command(),inject='after-create')
        self.assertEqual(client.request.call_count,2)

    def test_fault_after_start_does_not_retry(self):
        client=self.api()
        with self.assertRaisesRegex(TimeoutError,'post-start'):
            client.run(fixture_command(),inject='after-start')
        self.assertEqual(client.request.call_count,3)

    def test_rejects_unsupported_api(self):
        client=self.api()
        client.request.side_effect=[{'ApiVersion':'1.51','MinAPIVersion':'1.44'}]
        with self.assertRaisesRegex(RuntimeError,'requires API'):
            client.run(fixture_command())
        self.assertEqual(client.request.call_count,1)

    def test_deadline_prevents_request(self):
        client=DockerAPI([])
        client.connection=Mock()
        with self.assertRaises(TimeoutError):
            client.request('POST','/unused',time.monotonic()-1)
        client.connection.request.assert_not_called()

    def test_transport_error_closes_without_retry_and_records(self):
        records=[]
        client=DockerAPI(records)
        client.connection=Mock()
        client.connection.request.side_effect=TimeoutError('uncertain commit')
        with self.assertRaises(TimeoutError):
            client.request('POST','/unused',time.monotonic()+2,{})
        self.assertEqual(client.connection.request.call_count,1)
        client.connection.close.assert_called_once()
        self.assertEqual(len(records),1)
        self.assertIn('error',records[0])


if __name__=='__main__':
    unittest.main()
