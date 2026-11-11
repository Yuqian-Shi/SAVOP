use super::{
    helpers::{insert_rule, link_is_inter_bgp, prefixes_by_asn_cone},
    AppContext,
};
use crate::SavRule;
use std::collections::BTreeMap;

pub(super) fn generate(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    if ctx.config.roa_info.is_empty() || ctx.config.aspa_info.is_empty() {
        return BTreeMap::new();
    }

    let mut rules = BTreeMap::new();
    for link in ctx.links.values() {
        if !link_is_inter_bgp(ctx, link) {
            continue;
        }
        if !matches!(link.local_role.as_deref(), Some("peer" | "provider")) {
            continue;
        }
        let Some(remote_as) = link.remote_as.map(|asn| asn as i64) else {
            continue;
        };
        for (prefix, origin) in prefixes_by_asn_cone(ctx, remote_as) {
            insert_rule(
                &mut rules,
                SavRule {
                    prefix,
                    interface_name: link.interface_name.clone(),
                    source_app: "bar".to_string(),
                    origin,
                    is_interior: true,
                },
            );
        }
    }
    rules
}
