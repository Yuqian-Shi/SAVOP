use super::{
    helpers::{aspa_check, insert_rule, link_is_bgp},
    AppContext,
};
use crate::{BirdRoute, SavRule};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn generate(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    if ctx.config.roa_info.is_empty() || ctx.config.aspa_info.is_empty() {
        return BTreeMap::new();
    }

    let provider_interfaces: BTreeSet<String> = ctx
        .links
        .values()
        .filter(|link| link_is_bgp(link))
        .filter(|link| link.remote_role.as_deref() == Some("provider"))
        .map(|link| link.interface_name.clone())
        .collect();
    if provider_interfaces.is_empty() {
        return BTreeMap::new();
    }

    let mut z: BTreeSet<i64> = ctx
        .links
        .values()
        .filter(|link| provider_interfaces.contains(&link.interface_name))
        .filter_map(|link| link.remote_as.map(|asn| asn as i64))
        .collect();

    let mut provider_prefixes = BTreeSet::new();
    for route in ctx.bird_routes {
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        if !provider_interfaces.contains(interface_name) {
            continue;
        }
        provider_prefixes.insert(route.prefix.clone());
        for path in candidate_paths(route) {
            add_path_cone(ctx, &path, &mut z);
        }
    }

    let mut current = z;
    loop {
        let mut next = current.clone();
        for asn in &current {
            if let Some(providers) = ctx.config.aspa_info.get(asn) {
                next.extend(providers.iter().copied());
            }
        }
        if next == current {
            break;
        }
        current = next;
    }

    let mut prefixes = provider_prefixes;
    for asn in &current {
        if let Some(roa_prefixes) = ctx.config.roa_info.get(asn) {
            prefixes.extend(roa_prefixes.iter().cloned());
        }
    }

    let mut rules = BTreeMap::new();
    for link in ctx.links.values() {
        if !link_is_bgp(link) || link.remote_role.as_deref() == Some("provider") {
            continue;
        }
        for prefix in &prefixes {
            insert_rule(
                &mut rules,
                SavRule {
                    prefix: prefix.clone(),
                    interface_name: link.interface_name.clone(),
                    source_app: "bicone".to_string(),
                    origin: -1,
                    is_interior: true,
                },
            );
        }
    }
    rules
}

fn candidate_paths(route: &BirdRoute) -> Vec<Vec<i64>> {
    let forward: Vec<i64> = route.as_path.iter().map(|asn| *asn as i64).collect();
    if forward.len() < 2 {
        return Vec::new();
    }
    let mut reverse = forward.clone();
    reverse.reverse();
    if reverse == forward {
        vec![forward]
    } else {
        vec![forward, reverse]
    }
}

fn add_path_cone(ctx: &AppContext<'_>, path: &[i64], z: &mut BTreeSet<i64>) {
    for index in 0..path.len().saturating_sub(1) {
        let provider = path[index];
        let customer = path[index + 1];
        if !aspa_check(ctx, customer, provider) {
            continue;
        }
        for asn in &path[index + 1..] {
            z.insert(*asn);
        }
    }
}
