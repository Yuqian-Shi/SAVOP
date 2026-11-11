use super::*;
use crate::sav_apps::{self, AppContext};
use crate::ConfigSummary;
use std::path::Path;

fn route(prefix: &str, interface: Option<&str>) -> KernelRoute {
    KernelRoute {
        family: if prefix.contains(':') { 6 } else { 4 },
        prefix: prefix.into(),
        interface_name: interface.map(str::to_owned),
        gateway: None,
        route_type: None,
        protocol: None,
        scope: None,
    }
}

fn expected(rows: &[KernelRoute], loose: bool) -> BTreeMap<String, SavRule> {
    let config = ConfigSummary::unloaded(Path::new("test-only"), "fixture");
    let links = BTreeMap::new();
    sav_apps::generate_sav_rules_for_app(
        &AppContext {
            config: &config,
            routes: rows,
            bird_routes: &[],
            links: &links,
        },
        if loose { "loose_urpf" } else { "strict_urpf" },
    )
}

fn check(cache: &mut UrpfRuleCache, rows: &[KernelRoute]) -> UpdateStats {
    let stats = cache.update(rows);
    assert_eq!(cache.rules(), &expected(rows, cache.loose));
    stats
}

#[test]
fn empty_snapshot_is_valid() {
    for loose in [false, true] {
        assert_eq!(
            check(&mut UrpfRuleCache::new(loose), &[]),
            UpdateStats::default()
        );
    }
}

#[test]
fn initial_ipv4_and_ipv6_equal_full_generation() {
    let rows = [
        route("192.0.2.0/24", Some("eth0")),
        route("2001:db8::/64", Some("eth1")),
    ];
    for loose in [false, true] {
        assert_eq!(check(&mut UrpfRuleCache::new(loose), &rows).added, 2);
    }
}

#[test]
fn no_change_reuses_rule_allocations() {
    let rows = [route("192.0.2.0/24", Some("eth0"))];
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        check(&mut cache, &rows);
        let before = cache.rules().values().next().unwrap().prefix.as_ptr();
        assert_eq!(
            check(&mut cache, &rows),
            UpdateStats {
                inspected: 1,
                added: 0,
                removed: 0
            }
        );
        assert_eq!(
            before,
            cache.rules().values().next().unwrap().prefix.as_ptr()
        );
    }
}

#[test]
fn strict_interface_change_only_replaces_affected_rule() {
    let mut cache = UrpfRuleCache::new(false);
    let mut rows = [
        route("192.0.2.0/24", Some("eth0")),
        route("198.51.100.0/24", Some("eth1")),
    ];
    check(&mut cache, &rows);
    rows[0].interface_name = Some("eth2".into());
    assert_eq!(
        check(&mut cache, &rows),
        UpdateStats {
            inspected: 2,
            added: 1,
            removed: 1
        }
    );
}

#[test]
fn loose_interface_change_is_noop() {
    let mut cache = UrpfRuleCache::new(true);
    check(&mut cache, &[route("192.0.2.0/24", Some("eth0"))]);
    assert_eq!(
        check(&mut cache, &[route("192.0.2.0/24", Some("eth9"))]),
        UpdateStats {
            inspected: 1,
            added: 0,
            removed: 0
        }
    );
}

#[test]
fn withdraw_and_readd() {
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        let rows = [route("192.0.2.0/24", Some("eth0"))];
        check(&mut cache, &rows);
        assert_eq!(check(&mut cache, &[]).removed, 1);
        assert_eq!(check(&mut cache, &rows).added, 1);
    }
}

#[test]
fn duplicate_rows_are_idempotent() {
    let row = route("192.0.2.0/24", Some("eth0"));
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        assert_eq!(check(&mut cache, &[row.clone(), row.clone()]).added, 1);
        assert_eq!(check(&mut cache, std::slice::from_ref(&row)).removed, 0);
        assert_eq!(check(&mut cache, &[]).removed, 1);
    }
}

#[test]
fn multiple_interfaces_do_not_withdraw_shared_loose_prefix() {
    let rows = [
        route("192.0.2.0/24", Some("eth0")),
        route("192.0.2.0/24", Some("eth1")),
    ];
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        assert_eq!(check(&mut cache, &rows).added, if loose { 1 } else { 2 });
        assert_eq!(
            check(&mut cache, &rows[1..]).removed,
            if loose { 0 } else { 1 }
        );
    }
}

#[test]
fn loopback_missing_and_empty_interfaces_preserve_existing_semantics() {
    let rows = [
        route("192.0.2.0/24", Some("lo")),
        route("198.51.100.0/24", None),
        route("203.0.113.0/24", Some("")),
    ];
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        assert_eq!(check(&mut cache, &rows).added, if loose { 3 } else { 1 });
        check(&mut cache, &rows[..1]);
    }
}

#[test]
fn metadata_change_does_not_recreate_rule() {
    let mut rows = [route("192.0.2.0/24", Some("eth0"))];
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        check(&mut cache, &rows);
        rows[0].gateway = Some("192.0.2.1".into());
        rows[0].protocol = Some("bird".into());
        assert_eq!(check(&mut cache, &rows).added, 0);
    }
}

#[test]
fn reordering_is_noop() {
    let mut rows = [
        route("192.0.2.0/24", Some("eth0")),
        route("2001:db8::/64", Some("eth1")),
    ];
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        check(&mut cache, &rows);
        rows.reverse();
        assert_eq!(
            check(&mut cache, &rows),
            UpdateStats {
                inspected: 2,
                added: 0,
                removed: 0
            }
        );
    }
}

#[test]
fn filtered_snapshot_change_removes_then_restores_rule() {
    let rows = [
        route("192.0.2.0/24", Some("eth0")),
        route("198.51.100.0/24", Some("eth1")),
    ];
    for loose in [false, true] {
        let mut cache = UrpfRuleCache::new(loose);
        check(&mut cache, &rows);
        assert_eq!(check(&mut cache, &rows[1..]).removed, 1);
        assert_eq!(check(&mut cache, &rows).added, 1);
    }
}

#[test]
fn app_caches_are_independent() {
    let mut caches = UrpfCaches::default();
    let rows = [route("192.0.2.0/24", Some("eth0"))];
    check(caches.get_mut("strict_urpf").unwrap(), &rows);
    assert!(caches.get_mut("loose_urpf").unwrap().rules().is_empty());
    check(caches.get_mut("loose_urpf").unwrap(), &rows);
    assert!(caches.get_mut("fp_urpf").is_none());
}

#[test]
fn epoch_exhaustion_rebuilds_safely() {
    let mut cache = UrpfRuleCache::new(false);
    check(&mut cache, &[route("192.0.2.0/24", Some("eth0"))]);
    cache.epoch = u64::MAX;
    check(&mut cache, &[route("198.51.100.0/24", Some("eth1"))]);
    assert_eq!(cache.epoch, 1);
}

#[test]
fn cached_dispatch_and_no_cache_fallback_are_equal() {
    let mut caches = UrpfCaches::default();
    let config = ConfigSummary::unloaded(Path::new("test-only"), "fixture");
    let links = BTreeMap::new();
    let rows = [route("192.0.2.0/24", Some("eth0"))];
    let ctx = AppContext {
        config: &config,
        routes: &rows,
        bird_routes: &[],
        links: &links,
    };
    for app in ["strict_urpf", "loose_urpf", "fp_urpf", "unknown"] {
        let full = sav_apps::with_sav_rules(&ctx, app, None, Clone::clone);
        let cached = sav_apps::with_sav_rules(&ctx, app, Some(&mut caches), Clone::clone);
        assert_eq!(cached, full);
    }
}

#[test]
fn aggregate_cached_table_matches_full_table() {
    let mut config = ConfigSummary::unloaded(Path::new("test-only"), "fixture");
    config.apps = vec!["strict_urpf".into(), "loose_urpf".into(), "fp_urpf".into()];
    let links = BTreeMap::new();
    let rows = [route("192.0.2.0/24", Some("eth0"))];
    let context = || AppContext {
        config: &config,
        routes: &rows,
        bird_routes: &[],
        links: &links,
    };
    let mut caches = UrpfCaches::default();
    assert_eq!(
        sav_apps::generate_sav_table(context(), Some(&mut caches)),
        sav_apps::generate_sav_table(context(), None)
    );
}

#[test]
fn randomized_snapshots_match_full_generator_after_every_step() {
    for loose in [false, true] {
        let mut seed = 20261019_u64;
        let mut rows = Vec::new();
        let mut cache = UrpfRuleCache::new(loose);
        for step in 0..500 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            if seed.is_multiple_of(3) && !rows.is_empty() {
                rows.remove(seed as usize % rows.len());
            } else {
                let prefix = if step % 2 == 0 {
                    format!("10.0.{}.0/24", seed % 17)
                } else {
                    format!("2001:db8:{:x}::/64", seed % 17)
                };
                rows.push(route(
                    &prefix,
                    [None, Some("lo"), Some("eth0"), Some("eth1")][seed as usize % 4],
                ));
            }
            check(&mut cache, &rows);
        }
        check(&mut cache, &[]);
    }
}

#[test]
fn concurrent_consumers_use_serialized_snapshots() {
    let shared = std::sync::Arc::new(std::sync::Mutex::new(UrpfRuleCache::new(false)));
    let workers: Vec<_> = (0..4)
        .map(|i| {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let rows = [route(&format!("10.0.{i}.0/24"), Some("eth0"))];
                for _ in 0..50 {
                    check(&mut shared.lock().unwrap(), &rows);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn single_and_many_interface_indexes_promote_and_compact() {
    let mut cache = UrpfRuleCache::new(false);
    let rows = [
        route("192.0.2.0/24", Some("eth0")),
        route("192.0.2.0/24", Some("eth1")),
        route("192.0.2.0/24", Some("eth2")),
    ];
    check(&mut cache, &rows[..1]);
    assert!(matches!(cache.seen["192.0.2.0/24"], Interfaces::One { .. }));
    check(&mut cache, &rows);
    assert!(matches!(cache.seen["192.0.2.0/24"], Interfaces::Many(_)));
    check(&mut cache, &rows[2..]);
    assert!(matches!(cache.seen["192.0.2.0/24"], Interfaces::One { .. }));
    check(&mut cache, &[]);
    assert!(cache.seen.is_empty());
}

#[test]
fn poisoned_cache_is_not_needed_for_full_fallback() {
    let shared = std::sync::Arc::new(std::sync::Mutex::new(UrpfCaches::default()));
    let owner = shared.clone();
    assert!(std::thread::spawn(move || {
        let _lock = owner.lock().unwrap();
        panic!("deliberately poison the cache");
    })
    .join()
    .is_err());
    let mut guard = shared.lock().ok();
    assert!(guard.is_none());
    let config = ConfigSummary::unloaded(Path::new("test-only"), "fixture");
    let links = BTreeMap::new();
    let rows = [route("192.0.2.0/24", Some("eth0"))];
    let ctx = AppContext {
        config: &config,
        routes: &rows,
        bird_routes: &[],
        links: &links,
    };
    assert_eq!(
        sav_apps::with_sav_rules(&ctx, "strict_urpf", guard.as_deref_mut(), Clone::clone),
        expected(&rows, false)
    );
}
