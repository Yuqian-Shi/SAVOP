# Adding a SAV App

SAV apps are implemented as small Rust modules under this directory. Each app converts the current router view into a SAV rule table:

- input: `AppContext`, which contains local config, kernel routes, parsed BIRD routes, and link metadata.
- output: `BTreeMap<String, SavRule>`, keyed through `helpers::insert_rule`.

Keep the app implementation deterministic and side-effect free. Runtime I/O, BIRD queries, HTTP handling, and nftables installation belong in the agent runtime, not inside a SAV app module.

## Add A New App

1. Create a file named after the app id:

```rust
// agent/src/sav_apps/my_app.rs
use super::{helpers::insert_rule, AppContext};
use crate::SavRule;
use std::collections::BTreeMap;

pub(super) fn generate(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    let mut rules = BTreeMap::new();

    for route in ctx.routes {
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        insert_rule(
            &mut rules,
            SavRule {
                prefix: route.prefix.clone(),
                interface_name: interface_name.to_string(),
                source_app: "my_app".to_string(),
                origin: -1,
                is_interior: true,
            },
        );
    }

    rules
}
```

2. Register the module in `mod.rs`:

```rust
mod my_app;
```

3. Add the app id to `DEFAULT_APP_IDS` if it should be available by default:

```rust
"my_app",
```

4. Add a dispatch arm in `generate_sav_rules_for_app`:

```rust
"my_app" => my_app::generate(ctx),
```

5. Enable it in a lab config when needed:

```json
{
  "sav_apps": ["my_app"],
  "active_sav_app": "my_app"
}
```

If `sav_apps` is empty or omitted, the agent uses `DEFAULT_APP_IDS`.

## Use Existing Inputs

Prefer these existing `AppContext` fields before adding new runtime state:

- `ctx.routes`: kernel FIB routes after filtering.
- `ctx.bird_routes`: parsed selected BIRD routes with AS-path information when available.
- `ctx.links`: per-link metadata, including interface name, roles, remote AS, and link type.
- `ctx.config`: local AS, router id, prefixes, ROA/ASPA maps, ignore-net policy, and active app settings.

Shared helpers live in `helpers.rs`. Use them for common behavior such as rule insertion, link role lookup, route origin inference, ROA checks, ASPA checks, and AS-cone expansion.

## Naming Rules

- Use a stable lowercase snake_case app id.
- Keep the file name identical to the app id when possible.
- Set `SavRule.source_app` to the same app id used in `DEFAULT_APP_IDS` and lab configs.
- Avoid aliases unless the app intentionally exposes variants, such as `efp_urpf_a_roa` and `efp_urpf_a_aspa`.

## Network-Interactive Apps

Most SAV apps are pure table-generation logic. If a new app needs protocol interaction between routers, update the agent runtime separately:

- add any message parsing or event handling outside `sav_apps/`;
- make the generated `sa.json` include the required app and per-link metadata;
- include the app id in `SAV_TABLE_STABLE_APPS` for benchmark auto-detection if SAV-table convergence must be measured;
- verify both FIB stability and SAV-table stability in the benchmark output.

Do not put sockets, polling loops, HTTP handlers, or BIRD command execution inside the app module.

## Validation

Run these checks before publishing a new app:

```sh
cargo fmt --all -- --check
cargo test --workspace --bins
cargo build --release --workspace --bins
KEEP_LAST=0 WAIT=90 ROUTE_STABLE_HOLD=5 SAV_TABLE_STABLE_HOLD=5 target/release/savop lab run 5_nodes_v6.json
```

For a network-interactive app, also run a topology where that app is active and confirm that `sav_table_stable_complete=1` in the benchmark summary.
