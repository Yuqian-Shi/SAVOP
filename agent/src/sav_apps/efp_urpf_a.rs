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
    let mut origin_prefixes: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    let mut customer_hits: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for route in ctx.routes {
        let origin = route_origin(ctx, route);
        if use_roa && !prefix_allowed_by_roa(ctx, origin, &route.prefix) {
            continue;
        }
        origin_prefixes
            .entry(origin)
            .or_default()
            .insert(route.prefix.clone());
        if let Some(interface_name) = route.interface_name.as_deref() {
            if link_role(ctx, interface_name).as_deref() == Some("customer") {
                if use_aspa && !customer_link_allowed_by_aspa(ctx, interface_name) {
                    continue;
                }
                customer_hits
                    .entry(interface_name.to_string())
                    .or_default()
                    .insert(origin);
            }
        }
    }

    build_rules(app_id, origin_prefixes, customer_hits)
}

fn from_bird(
    ctx: &AppContext<'_>,
    app_id: &str,
    use_roa: bool,
    use_aspa: bool,
) -> BTreeMap<String, SavRule> {
    let mut origin_prefixes: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    let mut customer_hits: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for route in ctx.bird_routes {
        let origin = bird_origin(route).unwrap_or(-1);
        if use_roa && !prefix_allowed_by_roa(ctx, origin, &route.prefix) {
            continue;
        }
        origin_prefixes
            .entry(origin)
            .or_default()
            .insert(route.prefix.clone());
        if let Some(interface_name) = route.interface_name.as_deref() {
            if link_role(ctx, interface_name).as_deref() == Some("customer") {
                if use_aspa && !customer_link_allowed_by_aspa(ctx, interface_name) {
                    continue;
                }
                customer_hits
                    .entry(interface_name.to_string())
                    .or_default()
                    .insert(origin);
            }
        }
    }

    build_rules(app_id, origin_prefixes, customer_hits)
}

fn build_rules(
    app_id: &str,
    origin_prefixes: BTreeMap<i64, BTreeSet<String>>,
    customer_hits: BTreeMap<String, BTreeSet<i64>>,
) -> BTreeMap<String, SavRule> {
    let mut rules = BTreeMap::new();
    for (interface_name, origins) in customer_hits {
        for origin in origins {
            if let Some(prefixes) = origin_prefixes.get(&origin) {
                for prefix in prefixes {
                    insert_rule(
                        &mut rules,
                        SavRule {
                            prefix: prefix.clone(),
                            interface_name: interface_name.clone(),
                            source_app: app_id.to_string(),
                            origin,
                            is_interior: true,
                        },
                    );
                }
            }
        }
    }
    rules
}
