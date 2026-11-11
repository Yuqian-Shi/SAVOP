use super::AppContext;
use crate::SavRule;
use std::collections::BTreeMap;

pub(super) fn generate(_ctx: &AppContext<'_>) -> BTreeMap<String, SavRule> {
    BTreeMap::new()
}
