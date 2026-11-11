"""Low-rate UDP probes for the isolated five-AS fixture (stdlib, Linux).

Run inside a lab network namespace only. Raw Ethernet permits an explicit
ingress and source address; the receiving UDP socket measures post-filter
delivery, unlike packet capture alone. No reflection or flood functionality.
"""
import argparse
import ipaddress
import json
import socket
import struct
import subprocess
import time


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def receive(args):
    if not 0.1 <= args.duration <= 180:
        raise ValueError("Receiver duration must be between 0.1 and 180 seconds")
    addr = ipaddress.ip_address(args.destination)
    sock = socket.socket(socket.AF_INET if addr.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind((str(addr), args.port))
    sock.settimeout(0.15)
    print("READY", flush=True)
    deadline, records = time.monotonic() + args.duration, []
    while time.monotonic() < deadline:
        try:
            data, source = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if data.startswith((args.token + ":").encode()):
            records.append({"source": source[0], "payload": data.decode(), "monotonic": time.monotonic()})
    print(json.dumps({"received": len(records), "packets": records}), flush=True)


def send(args):
    src, dst = ipaddress.ip_address(args.source), ipaddress.ip_address(args.destination)
    if src.version != dst.version or not 1 <= args.count <= 20:
        raise ValueError("Same address family and 1..20 packets required")
    # Restrict this helper to laboratory ranges; the runner separately verifies
    # that every interface belongs to its owned, uplink-free namespaces.
    allowed = ipaddress.ip_network("198.18.0.0/15") if src.version == 4 else ipaddress.ip_network("fd42:2400::/32")
    if src not in allowed or dst not in allowed:
        raise ValueError("Probe addresses must be within the laboratory prefix")
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show", "dev", args.interface]))
    mac_src = bytes.fromhex(links[0]["address"].replace(":", ""))
    mac_dst = bytes.fromhex(args.peer_mac.replace(":", ""))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.interface, 0))
    lengths = []
    for i in range(args.count):
        payload = f"{args.token}:{i}".encode()
        udp_length = 8 + len(payload)
        udp = struct.pack("!HHHH", 19006, args.port, udp_length, 0) + payload
        if src.version == 4:
            pseudo = src.packed + dst.packed + struct.pack("!BBH", 0, 17, udp_length)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_length, i, 0, 32, 17, 0, src.packed, dst.packed)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            ethernet_type = 0x0800
        else:
            pseudo = src.packed + dst.packed + struct.pack("!I3xB", udp_length, 17)
            ip = struct.pack("!IHBB16s16s", 6 << 28, udp_length, 17, 32, src.packed, dst.packed)
            ethernet_type = 0x86DD
        udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
        lengths.append(sock.send(mac_dst + mac_src + struct.pack("!H", ethernet_type) + ip + udp))
        time.sleep(0.05)
    print(json.dumps({"sent": len(lengths), "frame_lengths": lengths, "source": str(src), "destination": str(dst)}))


def normal_send(args):
    """Use real host routing and an address owned by the sending namespace."""
    source, destination = ipaddress.ip_address(args.source), ipaddress.ip_address(args.destination)
    network = ipaddress.ip_network("198.18.0.0/15") if source.version == 4 else ipaddress.ip_network("fd42:2400::/32")
    if source.version != destination.version or source not in network or destination not in network or not 1 <= args.count <= 20:
        raise ValueError("Only low-rate laboratory probes are allowed")
    sock = socket.socket(socket.AF_INET if source.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind((str(source), 0))  # Do not enable FREEBIND: this must be a real local address.
    lengths = []
    for i in range(args.count):
        lengths.append(sock.sendto(f"{args.token}:{i}".encode(), (str(destination), args.port)))
        time.sleep(0.05)
    print(json.dumps({"sent": len(lengths), "payload_lengths": lengths, "source": str(source), "destination": str(destination), "source_port": sock.getsockname()[1]}))


def normal_stream(args):
    """Bounded low-rate stream for observing a controlled route transition."""
    source, destination = ipaddress.ip_address(args.source), ipaddress.ip_address(args.destination)
    network = ipaddress.ip_network("198.18.0.0/15") if source.version == 4 else ipaddress.ip_network("fd42:2400::/32")
    if (source.version != destination.version or source not in network or destination not in network
            or not 1 <= args.duration <= 120 or not 200 <= args.interval_ms <= 5000):
        raise ValueError("Use lab addresses, duration <=120 seconds, and a rate no higher than 5 packets/second")
    sock = socket.socket(socket.AF_INET if source.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind((str(source), 0))
    started = time.monotonic()
    deadline = started + args.duration
    interval = args.interval_ms / 1000
    records, sequence = [], 0
    while time.monotonic() < deadline:
        sent_at = time.monotonic()
        payload = f"{args.token}:{sequence}".encode()
        length = sock.sendto(payload, (str(destination), args.port))
        records.append({"seq": sequence, "send_monotonic": sent_at, "bytes": length})
        sequence += 1
        remaining = started + sequence * interval - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    print(json.dumps({"sent": len(records), "start_monotonic": started,
                      "stop_monotonic": time.monotonic(), "interval_ms": args.interval_ms,
                      "source": str(source), "destination": str(destination), "packets": records}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("receive", "send", "normal-send", "normal-stream"))
    parser.add_argument("--destination", required=True)
    parser.add_argument("--source")
    parser.add_argument("--interface")
    parser.add_argument("--peer-mac")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--duration", type=float, default=2.5)
    parser.add_argument("--interval-ms", type=int, default=200)
    parser.add_argument("--port", type=int, default=19005)
    parser.add_argument("--token", required=True)
    options = parser.parse_args()
    {"receive": receive, "send": send, "normal-send": normal_send, "normal-stream": normal_stream}[options.mode](options)
