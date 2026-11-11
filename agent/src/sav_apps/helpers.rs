use super::AppContext;
use crate::{BirdRoute, KernelRoute, LinkState, SavRule};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn rules_from_routes(
    app_id: &str,
    routes: &[KernelRoute],
    loose: bool,
) -> BTreeMap<String, SavRule> {
    let mut rules = BTreeMap::new();
    for route in routes {
        let interface_name = if loose {
            "*".to_string()
        } else if let Some(interface_name) = &route.interface_name {
            interface_name.clone()
        } else {
            continue;
        };
        if interface_name == "lo" {
            continue;
        }
        insert_rule(
            &mut rules,
            SavRule {
                prefix: route.prefix.clone(),
                interface_name,
                source_app: app_id.to_string(),
                origin: -1,
                is_interior: true,
            },
        );
    }
    rules
}

pub(super) fn prefixes_by_asn_cone(ctx: &AppContext<'_>, root_asn: i64) -> BTreeMap<String, i64> {
    let mut prefixes = BTreeMap::new();
    let mut ases = BTreeSet::new();
    ases.insert(root_asn);
    if let Some(root_prefixes) = ctx.config.roa_info.get(&root_asn) {
        for prefix in root_prefixes {
            prefixes.insert(prefix.clone(), root_asn);
        }
    }

    loop {
        let mut added = false;
        for (customer_asn, providers) in &ctx.config.aspa_info {
            if !providers.iter().any(|provider| ases.contains(provider)) {
                continue;
            }
            if ases.insert(*customer_asn) {
                if let Some(roa_prefixes) = ctx.config.roa_info.get(customer_asn) {
                    for prefix in roa_prefixes {
                        prefixes.entry(prefix.clone()).or_insert(*customer_asn);
                    }
                }
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    prefixes
}

pub(super) fn prefix_allowed_by_roa(ctx: &AppContext<'_>, origin: i64, prefix: &str) -> bool {
    ctx.config
        .roa_info
        .get(&origin)
        .map(|prefixes| prefixes.contains(prefix))
        .unwrap_or(false)
}

pub(super) fn customer_link_allowed_by_aspa(ctx: &AppContext<'_>, interface_name: &str) -> bool {
    let Some(local_as) = ctx.config.local_as.map(|asn| asn as i64) else {
        return false;
    };
    let Some(link) = link_by_interface(ctx, interface_name) else {
        return false;
    };
    let Some(customer_as) = link.remote_as.map(|asn| asn as i64) else {
        return false;
    };
    aspa_check(ctx, customer_as, local_as)
}

pub(super) fn aspa_check(ctx: &AppContext<'_>, customer: i64, provider: i64) -> bool {
    ctx.config
        .aspa_info
        .get(&customer)
        .map(|providers| providers.contains(&provider))
        .unwrap_or(false)
}

pub(super) fn route_origin(ctx: &AppContext<'_>, route: &KernelRoute) -> i64 {
    if let Some(interface_name) = route.interface_name.as_deref() {
        if let Some(link) = link_by_interface(ctx, interface_name) {
            if let Some(remote_as) = link.remote_as {
                return remote_as as i64;
            }
        }
    }
    ctx.config.local_as.map(|asn| asn as i64).unwrap_or(-1)
}

pub(super) fn bird_origin(route: &BirdRoute) -> Option<i64> {
    route.origin_as.map(|origin| origin as i64)
}

pub(super) fn interface_origin(ctx: &AppContext<'_>, interface_name: &str) -> Option<i64> {
    link_by_interface(ctx, interface_name)
        .and_then(|link| link.remote_as)
        .map(|asn| asn as i64)
}

pub(super) fn link_role(ctx: &AppContext<'_>, interface_name: &str) -> Option<String> {
    link_by_interface(ctx, interface_name)
        .and_then(|link| link.remote_role.clone().or_else(|| link.local_role.clone()))
}

pub(super) fn link_is_bgp(link: &LinkState) -> bool {
    matches!(link.link_type.as_deref(), Some("bgp" | "bgp_rpdp" | "dsav"))
}

pub(super) fn link_is_inter_bgp(ctx: &AppContext<'_>, link: &LinkState) -> bool {
    if !link_is_bgp(link) {
        return false;
    }
    if let Some(is_interior) = link.is_interior {
        return is_interior;
    }
    match (ctx.config.local_as, link.remote_as) {
        (Some(local_as), Some(remote_as)) => local_as != remote_as,
        _ => true,
    }
}

fn link_by_interface<'a>(ctx: &'a AppContext<'_>, interface_name: &str) -> Option<&'a LinkState> {
    ctx.links
        .values()
        .find(|link| link.interface_name == interface_name)
}

pub(super) fn insert_rule(rules: &mut BTreeMap<String, SavRule>, rule: SavRule) {
    rules.insert(sav_rule_key(&rule), rule);
}

fn sav_rule_key(rule: &SavRule) -> String {
    format!("{}_{}_{}", rule.prefix, rule.origin, rule.interface_name)
}
