"""Experimental local Docker API transport for the exact capacity-run command.

No daemon configuration, image pulls, network access or automatic mutation retry.
The caller retains the existing name/label recovery and owned-ID cleanup.
"""
import http.client
import json
import re
import socket
import time
from pathlib import PurePosixPath
from urllib.parse import urlencode


def payload_from_run(argv):
    if argv[:3] != ['docker', 'run', '-d']:
        raise ValueError('Only the detached capacity command is supported')
    repeated = {'--label', '--cap-add', '--mount', '--sysctl', '--security-opt'}
    single = {'--name', '--network', '--memory', '--memory-swap', '--cpus', '--pids-limit', '--entrypoint'}
    opts, index = {}, 3
    while index < len(argv) and argv[index].startswith('--'):
        key = argv[index]
        if key not in repeated | single or index + 1 >= len(argv):
            raise ValueError('Unsupported Docker argument: ' + key)
        if key in single and key in opts:
            raise ValueError('Duplicate argument: ' + key)
        opts.setdefault(key, []).append(argv[index + 1])
        index += 2
    if set(opts) != repeated | single or len(argv[index:]) != 2:
        raise ValueError('Incomplete capacity command')
    one = lambda key: opts[key][0]
    image, command = argv[index:]
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or command != 'infinity'
            or one('--network') != 'none' or one('--entrypoint') != '/bin/sleep'
            or one('--memory') != '512m' or one('--memory-swap') != '512m'
            or one('--cpus') != '1' or one('--pids-limit') != '128'
            or set(opts['--cap-add']) != {'NET_ADMIN', 'NET_RAW'}
            or opts['--security-opt'] != ['no-new-privileges']):
        raise ValueError('Unexpected capacity safety settings')
    name = one('--name')
    if not re.fullmatch(r'k5-[a-z0-9-]+-n[0-9]+', name):
        raise ValueError('Invalid owned name')
    labels = dict(item.split('=', 1) for item in opts['--label'])
    run_id = name[3:name.rindex('-n')]
    if labels != {'org.savop.k5-validation': run_id}:
        raise ValueError('Owned name/label mismatch')
    mounts = []
    for item in opts['--mount']:
        parts = dict((part.split('=', 1) if '=' in part else (part, True)) for part in item.split(','))
        if set(parts) - {'type', 'source', 'target', 'readonly'} or parts.get('type') != 'bind':
            raise ValueError('Unexpected mount')
        source = str(parts.get('source', ''))
        if (not source.startswith('/mnt/hdd/k5-capacity-') or '..' in PurePosixPath(source).parts
                or '\\' in source):
            raise ValueError('Mount outside dedicated data-volume experiment')
        mounts.append(dict(Type='bind', Source=parts['source'], Target=parts['target'],
                           ReadOnly=bool(parts.get('readonly', False))))
    if len(mounts) != 2 or {(m['Target'], m['ReadOnly']) for m in mounts} != {('/build', True), ('/node', False)}:
        raise ValueError('Unexpected mount layout')
    paths = {m['Target']: PurePosixPath(m['Source']) for m in mounts}
    if paths['/build'].parent != PurePosixPath('/mnt/hdd'):
        raise ValueError('Invalid build root')
    node_id = name.rsplit('-n', 1)[1]
    if paths['/node'] != paths['/build']/('savop_run_'+run_id)/node_id:
        raise ValueError('Node bind does not belong to this run')
    sysctls = dict(item.split('=', 1) for item in opts['--sysctl'])
    expected = {'net.ipv4.ip_forward': '1', 'net.ipv4.conf.all.rp_filter': '0',
                'net.ipv4.conf.default.rp_filter': '0', 'net.ipv6.conf.all.forwarding': '1',
                'net.ipv6.conf.all.disable_ipv6': '0', 'net.ipv6.conf.default.disable_ipv6': '0',
                'net.ipv6.conf.default.keep_addr_on_down': '1'}
    if sysctls != expected:
        raise ValueError('Unexpected sysctls')
    return name, dict(Image=image, Entrypoint=['/bin/sleep'], Cmd=['infinity'], Labels=labels,
                      AttachStdin=False, AttachStdout=False, AttachStderr=False, Tty=False, OpenStdin=False,
                      HostConfig=dict(NetworkMode='none', Privileged=False, CapAdd=opts['--cap-add'],
                                      SecurityOpt=opts['--security-opt'], Memory=512*1024**2,
                                      MemorySwap=512*1024**2, NanoCpus=10**9, PidsLimit=128,
                                      Mounts=mounts, Sysctls=sysctls))


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, timeout):
        super().__init__('localhost', timeout=timeout)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


class DockerAPI:
    def __init__(self, records):
        self.records = records
        self.connection = UnixConnection(45)
        self.version = None

    def close(self):
        self.connection.close()

    def request(self, method, path, deadline, payload=None, expected=200):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Container creation deadline exhausted')
        self.connection.timeout = remaining
        if self.connection.sock:
            self.connection.sock.settimeout(remaining)
        body = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        row = dict(method=method, path=path, request=payload, started=time.time(), start=time.monotonic())
        try:
            self.connection.request(method, path, body=body, headers={'Content-Type': 'application/json'})
            response = self.connection.getresponse()
            raw = response.read()
            value = json.loads(raw) if raw else None
            row.update(status=response.status, response=value)
            if response.status != expected:
                raise RuntimeError(f'Docker API {method} {path}: {response.status}: {value}')
            return value
        except Exception as error:
            row['error'] = repr(error)
            self.close()  # No automatic retry of a possibly completed mutation.
            raise
        finally:
            row['seconds'] = time.monotonic() - row['start']
            self.records.append(row)

    def run(self, argv, timeout=45, inject=None):
        name, payload = payload_from_run(argv)
        deadline = time.monotonic() + timeout
        if self.version is None:
            version = self.request('GET', '/version', deadline)
            if not re.fullmatch(r'1\.[0-9]+', version['ApiVersion']):
                raise RuntimeError('Invalid daemon API version')
            if not int(version['MinAPIVersion'].split('.')[1]) <= 52 <= int(version['ApiVersion'].split('.')[1]):
                raise RuntimeError('This experiment requires API v1.52 support')
            self.version = 'v1.52'
        response = self.request('POST', '/' + self.version + '/containers/create?' + urlencode({'name': name}),
                                deadline, payload, expected=201)
        cid = response['Id']
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            raise RuntimeError('Invalid full container ID')
        if inject == 'after-create':
            raise TimeoutError('Injected post-create response loss')
        self.request('POST', f'/{self.version}/containers/{cid}/start', deadline, expected=204)
        if inject == 'after-start':
            raise TimeoutError('Injected post-start response loss')
        return cid
