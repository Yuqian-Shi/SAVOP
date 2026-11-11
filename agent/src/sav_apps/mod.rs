use crate::{BirdRoute, ConfigSummary, KernelRoute, LinkState, SavRule};
use std::collections::{BTreeMap, BTreeSet};

mod bar;
mod bicone;
mod efp_urpf_a;
mod efp_urpf_b;
mod fp_urpf;
mod helpers;
mod loose_urpf;
mod passport;
mod rpdp;
mod strict_urpf;
pub(crate) mod urpf_cache;

pub const DEFAULT_APP_IDS: &[&str] = &[
    "rpdp",
    "strict_urpf",
    "loose_urpf",
    "fp_urpf",
    "efp_urpf_a",
    "efp_urpf_b",
    "efp_urpf_a_roa",
    "efp_urpf_b_roa",
    "efp_urpf_a_aspa",
    "efp_urpf_b_aspa",
    "efp_urpf_a_roa_aspa",
    "efp_urpf_b_roa_aspa",
    "bar",
    "bicone",
    "passport",
];

pub struct AppContext<'a> {
    pub config: &'a ConfigSummary,
    pub routes: &'a [KernelRoute],
    pub bird_routes: &'a [BirdRoute],
    pub links: &'a BTreeMap<String, LinkState>,
}

pub type SavTable = BTreeMap<String, BTreeMap<String, SavRule>>;

pub fn default_app_ids() -> Vec<String> {
    DEFAULT_APP_IDS
        .iter()
        .map(|app| (*app).to_string())
        .collect()
}

pub fn is_known_app_id(app_id: &str) -> bool {
    DEFAULT_APP_IDS.contains(&app_id)
}

pub fn active_app_ids(configured: &[String]) -> Vec<String> {
    if configured.is_empty() {
        return default_app_ids();
    }
    let mut seen = BTreeSet::new();
    let mut apps = Vec::new();
    for app in configured {
        if seen.insert(app.clone()) {
            apps.push(app.clone());
        }
    }
    apps
}

pub fn generate_sav_table(
    ctx: AppContext<'_>,
    caches: Option<&mut urpf_cache::UrpfCaches>,
) -> SavTable {
    let mut caches = caches;
    let mut table = BTreeMap::new();
    for app_id in active_app_ids(&ctx.config.apps) {
        let rules = with_sav_rules(&ctx, &app_id, caches.as_deref_mut(), Clone::clone);
        table.insert(app_id.clone(), rules);
    }
    table
}

/// Consume cached rules by reference. A missing cache preserves the full path.
pub(crate) fn with_sav_rules<R>(
    ctx: &AppContext<'_>,
    app: &str,
    caches: Option<&mut urpf_cache::UrpfCaches>,
    consume: impl FnOnce(&BTreeMap<String, SavRule>) -> R,
) -> R {
    if let Some(cache) = caches.and_then(|c| c.get_mut(app)) {
        cache.update(ctx.routes);
        consume(cache.rules())
    } else {
        consume(&generate_sav_rules_for_app(ctx, app))
    }
}

pub fn generate_sav_rules_for_app(ctx: &AppContext<'_>, app_id: &str) -> BTreeMap<String, SavRule> {
    match app_id {
        "strict_urpf" => strict_urpf::generate(ctx),
        "loose_urpf" => loose_urpf::generate(ctx),
        "fp_urpf" => fp_urpf::generate(ctx),
        "efp_urpf_a" => efp_urpf_a::generate(ctx, "efp_urpf_a", false, false),
        "efp_urpf_b" => efp_urpf_b::generate(ctx, "efp_urpf_b", false, false),
        "efp_urpf_a_roa" => efp_urpf_a::generate(ctx, "efp_urpf_a_roa", true, false),
        "efp_urpf_b_roa" => efp_urpf_b::generate(ctx, "efp_urpf_b_roa", true, false),
        "efp_urpf_a_aspa" => efp_urpf_a::generate(ctx, "efp_urpf_a_aspa", false, true),
        "efp_urpf_b_aspa" => efp_urpf_b::generate(ctx, "efp_urpf_b_aspa", false, true),
        "efp_urpf_a_roa_aspa" => efp_urpf_a::generate(ctx, "efp_urpf_a_roa_aspa", true, true),
        "efp_urpf_b_roa_aspa" => efp_urpf_b::generate(ctx, "efp_urpf_b_roa_aspa", true, true),
        "rpdp" => rpdp::generate(ctx),
        "bar" => bar::generate(ctx),
        "bicone" => bicone::generate(ctx),
        "passport" => passport::generate(ctx),
        _ => BTreeMap::new(),
    }
}
