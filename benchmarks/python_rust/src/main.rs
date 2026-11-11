#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/production.rs"));

#[derive(serde::Deserialize)]
struct BenchRow {
    prefix: String,
    interface: String,
    origin: u64,
}
#[derive(serde::Deserialize)]
struct BenchInput {
    family: u8,
    states: Vec<Vec<BenchRow>>,
}

fn bench_memory_kib(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|s| s.starts_with(key))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn bench_canonical(rules: &BTreeMap<String, SavRule>) -> Vec<(String, String, String, i64, bool)> {
    let mut rows: Vec<_> = rules
        .values()
        .map(|r| {
            (
                r.prefix.clone(),
                r.interface_name.clone(),
                r.source_app.clone(),
                r.origin,
                r.is_interior,
            )
        })
        .collect();
    rows.sort();
    rows
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 5, "worker fixture app mode iterations");
    let fixture: BenchInput = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    let app = &args[2];
    let mode = &args[3];
    let iterations: usize = args[4].parse().unwrap();
    let mut config = ConfigSummary::unloaded(Path::new("benchmark-only"), "fixture");
    config.config_loaded = true;
    config.config_error = None;
    config.local_as = Some(64512);
    let links = BTreeMap::new();
    let kernel_states: Vec<Vec<KernelRoute>> = fixture
        .states
        .iter()
        .map(|state| {
            state
                .iter()
                .map(|r| KernelRoute {
                    family: fixture.family,
                    prefix: r.prefix.clone(),
                    interface_name: Some(r.interface.clone()),
                    gateway: None,
                    route_type: None,
                    protocol: None,
                    scope: None,
                })
                .collect()
        })
        .collect();
    let bird_states: Vec<Vec<BirdRoute>> = fixture
        .states
        .iter()
        .map(|state| {
            state
                .iter()
                .map(|r| BirdRoute {
                    prefix: r.prefix.clone(),
                    interface_name: Some(r.interface.clone()),
                    as_path: vec![r.origin],
                    origin_as: Some(r.origin),
                    selected: true,
                })
                .collect()
        })
        .collect();
    drop(fixture);
    let generate = |state: usize| {
        sav_apps::generate_sav_rules_for_app(
            &sav_apps::AppContext {
                config: &config,
                routes: &kernel_states[state],
                bird_routes: &bird_states[state],
                links: &links,
            },
            app,
        )
    };
    let incremental = std::env::var("SAVOP_BENCH_RULE_PATH").as_deref() == Ok("incremental")
        && matches!(app.as_str(), "strict_urpf" | "loose_urpf");
    let context = |state: usize| sav_apps::AppContext {
        config: &config,
        routes: &kernel_states[state],
        bird_routes: &bird_states[state],
        links: &links,
    };
    if mode == "verify" {
        let mut caches = sav_apps::urpf_cache::UrpfCaches::default();
        let states: Vec<_> = [0, 1, 0]
            .iter()
            .map(|s| {
                if incremental {
                    sav_apps::with_sav_rules(&context(*s), app, Some(&mut caches), bench_canonical)
                } else {
                    bench_canonical(&generate(*s))
                }
            })
            .collect();
        println!("{}", serde_json::to_string(&states).unwrap());
        return;
    }
    if incremental {
        let mut caches = sav_apps::urpf_cache::UrpfCaches::default();
        for state in [0, 1] {
            sav_apps::with_sav_rules(&context(state), app, Some(&mut caches), |rules| {
                std::hint::black_box(rules).len()
            });
        }
        if mode == "update" {
            sav_apps::with_sav_rules(&context(0), app, Some(&mut caches), |rules| rules.len());
        } else {
            caches = sav_apps::urpf_cache::UrpfCaches::default();
        }
        let start = std::time::Instant::now();
        let mut count_sum = 0;
        let mut count = 0;
        for i in 0..iterations {
            let state = if mode == "update" { (i + 1) % 2 } else { 0 };
            // Full mode measures cold cache construction, not a warmed cache hit.
            if mode == "full" {
                caches = sav_apps::urpf_cache::UrpfCaches::default();
            }
            count = sav_apps::with_sav_rules(&context(state), app, Some(&mut caches), |rules| {
                std::hint::black_box(rules).len()
            });
            count_sum += count;
        }
        let elapsed_ns = start.elapsed().as_nanos();
        println!(
            "{}",
            serde_json::json!({"language":"rust", "rule_path":"incremental_snapshot",
            "elapsed_ns":elapsed_ns, "iterations":iterations, "count":count, "count_sum":count_sum,
            "peak_rss_kib":bench_memory_kib("VmHWM:"), "rss_kib":bench_memory_kib("VmRSS:")})
        );
        return;
    }
    // Two untimed warm-up calls, then a known initial table. Both states are pre-parsed.
    drop(generate(0));
    drop(generate(1));
    let mut rules = if mode == "update" {
        generate(0)
    } else {
        BTreeMap::new()
    };
    let start = std::time::Instant::now();
    let mut count_sum: usize = 0;
    for i in 0..iterations {
        let state = if mode == "update" { (i + 1) % 2 } else { 0 };
        if mode == "full" {
            rules.clear();
        }
        rules = std::hint::black_box(generate(state));
        count_sum += std::hint::black_box(rules.len());
    }
    let elapsed_ns = start.elapsed().as_nanos();
    println!(
        "{}",
        serde_json::json!({"language":"rust", "elapsed_ns":elapsed_ns,
        "iterations":iterations, "count":rules.len(), "count_sum":count_sum,
        "peak_rss_kib":bench_memory_kib("VmHWM:"), "rss_kib":bench_memory_kib("VmRSS:")})
    );
}
