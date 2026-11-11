"""Call original legacy algorithms, without importing/starting the full Agent."""
import importlib.util
import json
import logging
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
legacy = Path(os.environ["SAVOP_LEGACY_ROOT"])
sys.path[:0] = [str(legacy / "sav_agent"), str(legacy)]

def load_module(name):
    spec = importlib.util.spec_from_file_location(name, legacy / "sav_agent" / "sav_app" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

urpf = load_module("app_urpf")
fp = load_module("app_fp_urpf")
import netaddr

def memory_kib(key):
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(key):
            return int(line.split()[1])
    raise RuntimeError(key)

def canonical(rules):
    return sorted([str(r["prefix"]), r["interface_name"], r["source_app"], r["origin"], r["is_interior"]]
                  for r in rules.values())

class FixtureAgent:
    config = {"local_as": 64512}
    state = 0
    def get_fib(self, source, scope):
        assert source == "bird"
        return bird_states[self.state] if scope == ["remote"] else {}

fixture_path, app_id, mode, iterations = sys.argv[1:]
iterations = int(iterations)
fixture = json.loads(Path(fixture_path).read_text())
kernel_states, bird_states = [], []
for state in fixture["states"]:
    kernel, bird = {}, {}
    for row in state:
        prefix = netaddr.IPNetwork(row["prefix"])
        kernel[prefix] = {"Iface": row["interface"], "Use": row["interface"]}
        bird[prefix] = [{"origin_asn": row["origin"], "interface_name": row["interface"]}]
    kernel_states.append(kernel)
    bird_states.append(bird)
del fixture
agent = FixtureAgent()
logger = logging.getLogger("benchmark-null")
logger.disabled = True
app = (fp.FpUrpfApp(agent, app_id, logger) if app_id == "fp_urpf" else
       urpf.UrpfApp(agent, app_id, "loose" if app_id == "loose_urpf" else "strict", logger))
# Compute the actual FIB deltas outside the timed algorithm stage, like pre-parsed Rust inputs.
deltas = []
for target in (0, 1):
    old, new = kernel_states[1 - target], kernel_states[target]
    adds = {p: r for p, r in new.items() if p not in old or old[p] != r}
    dels = {p: r for p, r in old.items() if p not in new or new[p] != r}
    deltas.append((adds, dels))

def generate(state, rules, full=False):
    agent.state = state
    if full:
        adds, dels = app.generate_sav_rules(kernel_states[state], {}, {})
        return adds
    adds, dels = app.generate_sav_rules(*deltas[state], rules)
    for key in dels:
        rules.pop(key, None)
    rules.update(adds)
    return rules

if mode == "verify":
    rules = generate(0, {}, full=True)
    states = [canonical(rules)]
    for state in (1, 0):
        rules = generate(state, rules)
        states.append(canonical(rules))
    print(json.dumps(states, separators=(",", ":")))
    sys.exit(0)

generate(0, {}, full=True)
generate(1, {}, full=True)
rules = generate(0, {}, full=True) if mode == "update" else {}
count_sum = 0
start = time.perf_counter_ns()
for i in range(iterations):
    if mode == "full":
        rules.clear()
        rules = generate(0, rules, full=True)
    else:
        rules = generate((i + 1) % 2, rules)
    count_sum += len(rules)
elapsed = time.perf_counter_ns() - start
print(json.dumps({"language": "python", "elapsed_ns": elapsed, "iterations": iterations,
                  "count": len(rules), "count_sum": count_sum,
                  "peak_rss_kib": memory_kib("VmHWM:"), "rss_kib": memory_kib("VmRSS:")}))
