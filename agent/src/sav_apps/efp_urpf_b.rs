use super::{
    helpers::{
        bird_origin, customer_link_allowed_by_aspa, insert_rule, link_role, prefix_allowed_by_roa,
        route_origin,
    },
    AppContext,
};
use crate::SavRule;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn generate(
    ctx: &AppContext<'_>,
    app_id: &str,
    use_roa: bool,
    use_aspa: bool,
) -> BTreeMap<String, SavRule> {
    if !ctx.bird_routes.is_empty() {
        return from_bird(ctx, app_id, use_roa, use_aspa);
    }
    let mut customer_interfaces = BTreeSet::new();
    let mut customer_origins = BTreeSet::new();
    let mut p_set = BTreeSet::new();
    let mut q_set = BTreeSet::new();

    for route in ctx.routes {
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        let origin = route_origin(ctx, route);
        if use_roa && !prefix_allowed_by_roa(ctx, origin, &route.prefix) {
            continue;
        }
        let item = (route.prefix.clone(), origin);
        match link_role(ctx, interface_name).as_deref() {
            Some("customer") => {
                if use_aspa && !customer_link_allowed_by_aspa(ctx, interface_name) {
                    continue;
                }
                customer_interfaces.insert(interface_name.to_string());
                customer_origins.insert(origin);
                p_set.insert(item);
            }
            Some("peer") | Some("provider") => {
                if customer_origins.contains(&origin) {
                    q_set.insert(item);
                }
            }
            _ => {}
        }
    }

    let mut z_set = p_set;
    z_set.extend(q_set);
    build_rules(app_id, customer_interfaces, z_set)
}

fn from_bird(
    ctx: &AppContext<'_>,
    app_id: &str,
    use_roa: bool,
    use_aspa: bool,
) -> BTreeMap<String, SavRule> {
    let mut customer_interfaces = BTreeSet::new();
    let mut customer_origins = BTreeSet::new();
    let mut p_set = BTreeSet::new();
    let mut q_candidates = Vec::new();

    for route in ctx.bird_routes {
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        let origin = bird_origin(route).unwrap_or(-1);
        if use_roa && !prefix_allowed_by_roa(ctx, origin, &route.prefix) {
            continue;
        }
        let item = (route.prefix.clone(), origin);
        match link_role(ctx, interface_name).as_deref() {
            Some("customer") => {
                if use_aspa && !customer_link_allowed_by_aspa(ctx, interface_name) {
                    continue;
                }
                customer_interfaces.insert(interface_name.to_string());
                customer_origins.insert(origin);
                p_set.insert(item);
            }
            Some("peer") | Some("provider") => q_candidates.push(item),
            _ => {}
        }
    }

    let mut z_set = p_set;
    for item @ (_, origin) in q_candidates {
        if customer_origins.contains(&origin) {
            z_set.insert(item);
        }
    }
    build_rules(app_id, customer_interfaces, z_set)
}

fn build_rules(
    app_id: &str,
    customer_interfaces: BTreeSet<String>,
    z_set: BTreeSet<(String, i64)>,
) -> BTreeMap<String, SavRule> {
    let mut rules = BTreeMap::new();
    for interface_name in customer_interfaces {
        for (prefix, origin) in &z_set {
            insert_rule(
                &mut rules,
                SavRule {
                    prefix: prefix.clone(),
                    interface_name: interface_name.clone(),
                    source_app: app_id.to_string(),
                    origin: *origin,
                    is_interior: true,
                },
            );
        }
    }
    rules
}
