use super::{helpers::insert_rule, AppContext};
use crate::SavRule;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn generate(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    let local_prefixes: BTreeSet<String> = ctx
        .config
        .prefixes
        .iter()
        .map(|prefix| prefix.to_ascii_lowercase())
        .collect();
    if local_prefixes.is_empty() {
        return BTreeMap::new();
    }

    let mut rules = BTreeMap::new();
    for route in ctx.routes {
        if !local_prefixes.contains(&route.prefix) {
            continue;
        }
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        insert_rule(
            &mut rules,
            SavRule {
                prefix: route.prefix.clone(),
                interface_name: interface_name.to_string(),
                source_app: "rpdp".to_string(),
                origin: -1,
                is_interior: false,
            },
        );
    }
    rules
}
