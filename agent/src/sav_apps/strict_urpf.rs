use super::{helpers, AppContext};
use crate::SavRule;
use std::collections::BTreeMap;

pub(super) fn generate(ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    helpers::rules_from_routes("strict_urpf", ctx.routes, false)
}
