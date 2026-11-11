use super::{
    helpers::{bird_origin, insert_rule, interface_origin, route_origin},
    AppContext,
};
use crate::SavRule;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn generate(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    if !ctx.bird_routes.is_empty() {
        return from_bird(ctx);
    }
    let mut origin_prefixes: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    let mut origin_interfaces: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for route in ctx.routes {
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        let origin = route_origin(ctx, route);
        origin_prefixes
            .entry(origin)
            .or_default()
            .insert(route.prefix.clone());
        origin_interfaces
            .entry(origin)
            .or_default()
            .insert(interface_name.to_string());
    }

    build_rules("fp_urpf", origin_prefixes, origin_interfaces)
}

fn from_bird(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    let mut origin_prefixes: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    let mut origin_interfaces: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for route in ctx.bird_routes {
        let Some(interface_name) = route.interface_name.as_deref() else {
            continue;
        };
        let origin = bird_origin(route)
            .or_else(|| interface_origin(ctx, interface_name))
            .unwrap_or(-1);
        origin_prefixes
            .entry(origin)
            .or_default()
            .insert(route.prefix.clone());
        origin_interfaces
            .entry(origin)
            .or_default()
            .insert(interface_name.to_string());
    }

    build_rules("fp_urpf", origin_prefixes, origin_interfaces)
}

fn build_rules(
    app_id: &str,
    origin_prefixes: BTreeMap<i64, BTreeSet<String>>,
    origin_interfaces: BTreeMap<i64, BTreeSet<String>>,
) -> BTreeMap<String, SavRule> {
    let mut rules = BTreeMap::new();
    for (origin, prefixes) in origin_prefixes {
        let Some(interfaces) = origin_interfaces.get(&origin) else {
            continue;
        };
        for prefix in prefixes {
            for interface_name in interfaces {
                insert_rule(
                    &mut rules,
                    SavRule {
                        prefix: prefix.clone(),
                        interface_name: interface_name.clone(),
                        source_app: app_id.to_string(),
                        origin: -1,
                        is_interior: true,
                    },
                );
            }
        }
    }
    rules
}
