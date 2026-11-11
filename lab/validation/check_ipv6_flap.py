"""Isolated reproducer for Linux IPv6 static-address retention on admin flap."""
import argparse
import json
from pathlib import Path
import subprocess


def main(output):
    if output.exists():
        raise FileExistsError(output)
    rows = []
    script = ("set -eu; ip link add flaptest type dummy; ip link set flaptest up; "
              "ip -6 addr add fec::5:1/124 dev flaptest nodad; "
              "ip -j -6 addr show dev flaptest; ip link set flaptest down; "
              "ip link set flaptest up; ip -j -6 addr show dev flaptest")
    for keep in (0, 1):
        command = ["docker", "run", "--rm", "--name", f"k5-ipv6-retention-{keep}", "--label", "org.savop.k5-validation=ipv6-retention",
                   "--network", "none", "--cap-add", "NET_ADMIN", "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
                   "--sysctl", "net.ipv6.conf.default.disable_ipv6=0", "--sysctl", f"net.ipv6.conf.default.keep_addr_on_down={keep}",
                   "--entrypoint", "/bin/sh", "savop_runtime_clab:latest", "-c", script]
        result = subprocess.run(command, text=True, capture_output=True, check=True, timeout=30)
        snapshots = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(snapshots) == 2
        addresses = [{a["local"] for n in snapshot for a in n["addr_info"]} for snapshot in snapshots]
        assert "fec::5:1" in addresses[0]
        assert ("fec::5:1" in addresses[1]) == bool(keep)
        rows.append({"keep_addr_on_down": keep, "command": command, "before": snapshots[0], "after": snapshots[1], "stderr": result.stderr})
    with output.open("x") as handle:
        json.dump({"status": "reproduced_and_controlled", "rows": rows}, handle, indent=2)
    print(json.dumps({"status": "reproduced_and_controlled", "address_retained": [False, True]}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    main(p.parse_args().output)
