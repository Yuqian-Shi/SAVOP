"""Small UDP echo probe, exclusively for owned isolated laboratory namespaces."""
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import time


def check_address(value):
    address = ipaddress.ip_address(value)
    allowed = ipaddress.ip_network("198.18.0.0/15") if address.version == 4 else ipaddress.ip_network("fd42:2400::/32")
    if address not in allowed:
        raise ValueError("Laboratory addresses only")
    return address


def main(args):
    address = check_address(args.address)
    sock = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    if args.mode == "server":
        sock.bind((str(address), 19008))
        Path(args.ready).touch(exist_ok=False)
        received = 0
        while True:
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if data == b"capacity-stop":
                break
            if data.startswith((args.token + ":").encode()):
                received += 1
                sock.sendto(data, peer)
        print(json.dumps({"received": received}), flush=True)
    elif args.mode == "stop":
        sock.sendto(b"capacity-stop", (str(address), 19008))
    else:
        source = check_address(args.source)
        if source.version != address.version:
            raise ValueError("Mixed address families")
        sock.bind((str(source), 0))
        received, sent = [], []
        for i in range(3):
            data = f"{args.token}:{args.source}:{i}".encode()
            started = time.monotonic()
            sock.sendto(data, (str(address), 19008))
            sent.append(i)
            try:
                reply, peer = sock.recvfrom(2048)
                if reply == data and peer[0] == str(address):
                    received.append({"seq": i, "rtt_ms": (time.monotonic() - started) * 1000})
            except socket.timeout:
                pass
            time.sleep(0.02)
        print(json.dumps({"source": args.source, "destination": str(address), "sent": sent, "received": received}), flush=True)
    sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "client", "stop"))
    parser.add_argument("--address", required=True)
    parser.add_argument("--source")
    parser.add_argument("--token", required=True)
    parser.add_argument("--ready")
    main(parser.parse_args())
