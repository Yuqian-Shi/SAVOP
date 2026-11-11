//! Stateful uRPF projection of an authoritative, already-filtered route snapshot.
//!
//! Snapshot discovery is still O(N). Only changed rule entries are allocated or
//! removed. Duplicate routes are idempotent; loose mode keys by prefix rather
//! than interface, so an interface-only change leaves its rules untouched.
use crate::{KernelRoute, SavRule};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UpdateStats {
    pub(crate) inspected: usize,
    pub(crate) added: usize,
    pub(crate) removed: usize,
}

pub(crate) struct UrpfRuleCache {
    loose: bool,
    epoch: u64,
    seen: HashMap<String, Interfaces>,
    rules: BTreeMap<String, SavRule>,
}

// Most kernel FIB prefixes have one selected interface. Avoid one hash-table
// allocation and a second string hash per prefix in that common case, while
// keeping bounded lookup cost for prefixes with many distinct interfaces.
enum Interfaces {
    One { name: String, epoch: u64 },
    Many(HashMap<String, u64>),
}

impl Interfaces {
    /// Mark an interface, returning true only if it is newly present.
    fn mark(&mut self, interface: &str, current: u64) -> bool {
        match self {
            Self::One { name, epoch } if name == interface => {
                *epoch = current;
                false
            }
            Self::One { name, epoch } => {
                let mut entries = HashMap::new();
                entries.insert(std::mem::take(name), *epoch);
                entries.insert(interface.to_owned(), current);
                *self = Self::Many(entries);
                true
            }
            Self::Many(entries) => {
                if let Some(stamp) = entries.get_mut(interface) {
                    *stamp = current;
                    false
                } else {
                    entries.insert(interface.to_owned(), current);
                    true
                }
            }
        }
    }

    fn retain_current(&mut self, epoch: u64, mut remove: impl FnMut(&str)) -> bool {
        match self {
            Self::One { name, epoch: stamp } => {
                if *stamp == epoch {
                    true
                } else {
                    remove(name);
                    false
                }
            }
            Self::Many(entries) => {
                entries.retain(|name, stamp| {
                    if *stamp == epoch {
                        true
                    } else {
                        remove(name);
                        false
                    }
                });
                let keep = !entries.is_empty();
                if entries.len() == 1 {
                    let (name, stamp) = std::mem::take(entries).into_iter().next().unwrap();
                    *self = Self::One { name, epoch: stamp };
                }
                keep
            }
        }
    }
}

impl UrpfRuleCache {
    pub(crate) fn new(loose: bool) -> Self {
        Self {
            loose,
            epoch: 0,
            seen: HashMap::new(),
            rules: BTreeMap::new(),
        }
    }

    pub(crate) fn rules(&self) -> &BTreeMap<String, SavRule> {
        &self.rules
    }

    pub(crate) fn update(&mut self, routes: &[KernelRoute]) -> UpdateStats {
        // Reset on epoch exhaustion rather than trusting wrapped seen markers.
        if self.epoch == u64::MAX {
            self.seen.clear();
            self.rules.clear();
            self.epoch = 0;
        }
        self.epoch += 1;
        let epoch = self.epoch;
        let mut stats = UpdateStats {
            inspected: routes.len(),
            ..UpdateStats::default()
        };
        for route in routes {
            let interface = if self.loose {
                "*"
            } else {
                match route.interface_name.as_deref() {
                    Some("lo") | None => continue,
                    Some(name) => name,
                }
            };
            if let Some(interfaces) = self.seen.get_mut(&route.prefix) {
                if !interfaces.mark(interface, epoch) {
                    continue;
                }
            } else {
                self.seen.insert(
                    route.prefix.clone(),
                    Interfaces::One {
                        name: interface.to_owned(),
                        epoch,
                    },
                );
            }
            let rule = SavRule {
                prefix: route.prefix.clone(),
                interface_name: interface.to_owned(),
                source_app: if self.loose {
                    "loose_urpf"
                } else {
                    "strict_urpf"
                }
                .to_owned(),
                origin: -1,
                is_interior: true,
            };
            super::helpers::insert_rule(&mut self.rules, rule);
            stats.added += 1;
        }
        let rules = &mut self.rules;
        self.seen.retain(|prefix, interfaces| {
            interfaces.retain_current(epoch, |interface| {
                rules.remove(&format!("{prefix}_-1_{interface}"));
                stats.removed += 1;
            })
        });
        stats
    }
}

pub(crate) struct UrpfCaches {
    strict: UrpfRuleCache,
    loose: UrpfRuleCache,
}

impl Default for UrpfCaches {
    fn default() -> Self {
        Self {
            strict: UrpfRuleCache::new(false),
            loose: UrpfRuleCache::new(true),
        }
    }
}

impl UrpfCaches {
    pub(crate) fn get_mut(&mut self, app: &str) -> Option<&mut UrpfRuleCache> {
        match app {
            "strict_urpf" => Some(&mut self.strict),
            "loose_urpf" => Some(&mut self.loose),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
