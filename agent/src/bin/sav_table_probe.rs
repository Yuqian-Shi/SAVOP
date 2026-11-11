use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const CLONE_NEWNET: i32 = 0x4000_0000;

unsafe extern "C" {
    fn setns(fd: i32, nstype: i32) -> i32;
}

#[derive(Clone)]
struct Config {
    netns_prefix: String,
    nodes: Vec<String>,
    jobs: usize,
    timeout_ms: u64,
}

#[derive(Clone)]
struct ProbeResult {
    node: String,
    hash: String,
    rule_count: usize,
}

fn usage() -> ! {
    eprintln!(
        "usage: sav_table_probe --netns-prefix PREFIX [--jobs N] [--timeout-ms MS] --nodes NODE [NODE ...]"
    );
    std::process::exit(2);
}

fn parse_args() -> Config {
    let mut args = env::args().skip(1);
    let mut netns_prefix = None;
    let mut nodes = Vec::new();
    let mut jobs = 8_usize;
    let mut timeout_ms = 5000_u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--netns-prefix" => netns_prefix = args.next(),
            "--jobs" => {
                jobs = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--timeout-ms" => {
                timeout_ms = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--nodes" => {
                nodes.extend(args.by_ref());
                break;
            }
            value if value.starts_with('-') => usage(),
            value => nodes.push(value.to_string()),
        }
    }

    if nodes.is_empty() {
        usage();
    }
    let Some(netns_prefix) = netns_prefix else {
        usage();
    };
    if jobs == 0 {
        jobs = 1;
    }

    Config {
        netns_prefix,
        nodes,
        jobs,
        timeout_ms,
    }
}

fn enter_netns(cfg: &Config, node: &str) -> io::Result<()> {
    let ns_path = PathBuf::from(format!("/var/run/netns/{}{}", cfg.netns_prefix, node));
    let ns = File::open(ns_path)?;
    let rc = unsafe { setns(ns.as_raw_fd(), CLONE_NEWNET) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fetch_active_sav_table(timeout: Duration) -> io::Result<String> {
    let mut stream = TcpStream::connect("127.0.0.1:8888")?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(
        b"GET /active_sav_table/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )?;
    let _ = stream.shutdown(Shutdown::Write);
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let Some((_, body)) = response.split_once("\r\n\r\n") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response has no header separator",
        ));
    };
    Ok(body.to_string())
}

fn active_rules(value: &Value) -> Value {
    value
        .pointer("/data/rules")
        .cloned()
        .or_else(|| value.get("rules").cloned())
        .unwrap_or(Value::Null)
}

fn rule_count(value: &Value) -> usize {
    value.as_object().map(|rules| rules.len()).unwrap_or(0)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(items) => {
            let inner = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{inner}]")
        }
        Value::Object(map) => {
            let mut ordered = BTreeMap::new();
            for (key, value) in map {
                ordered.insert(key, value);
            }
            let inner = ordered
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        }
    }
}

fn hash_text(text: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn probe_node(cfg: &Config, node: &str) -> io::Result<ProbeResult> {
    enter_netns(cfg, node)?;
    let body = fetch_active_sav_table(Duration::from_millis(cfg.timeout_ms))?;
    let value: Value = serde_json::from_str(&body).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid active SAV table JSON: {err}"),
        )
    })?;
    let rules = active_rules(&value);
    let canonical = canonical_json(&rules);
    Ok(ProbeResult {
        node: node.to_string(),
        hash: hash_text(&canonical),
        rule_count: rule_count(&rules),
    })
}

fn main() {
    let cfg = Arc::new(parse_args());
    let next = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::<ProbeResult>::new()));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let jobs = cfg.jobs.min(cfg.nodes.len());

    let mut handles = Vec::new();
    for _ in 0..jobs {
        let cfg = Arc::clone(&cfg);
        let next = Arc::clone(&next);
        let results = Arc::clone(&results);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || loop {
            let idx = next.fetch_add(1, Ordering::Relaxed);
            let Some(node) = cfg.nodes.get(idx) else {
                break;
            };
            match probe_node(&cfg, node) {
                Ok(result) => results.lock().unwrap().push(result),
                Err(err) => errors.lock().unwrap().push(format!("{node}: {err}")),
            }
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    let mut results = results.lock().unwrap().clone();
    results.sort_by_key(|result| {
        result
            .node
            .parse::<u64>()
            .map(|num| (0, num, result.node.clone()))
            .unwrap_or_else(|_| (1, 0, result.node.clone()))
    });
    for result in results {
        println!("{},{},{}", result.node, result.hash, result.rule_count);
    }

    let errors = errors.lock().unwrap();
    if !errors.is_empty() {
        for err in errors.iter() {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}
