mod auto_dataplane;
mod sav_apps;

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct Config {
    data_path: PathBuf,
    config_path: PathBuf,
    signal_path: PathBuf,
    log_dir: PathBuf,
    exec_results_path: PathBuf,
    bird_logfile: PathBuf,
    bird_bin: String,
    bird_config: String,
    bird_socket: PathBuf,
    bird_pid_file: Option<PathBuf>,
    listen_addr: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ConfigSummary {
    pub(crate) config_loaded: bool,
    pub(crate) config_error: Option<String>,
    pub(crate) config_path: String,
    pub(crate) device_id: String,
    pub(crate) local_as: Option<u64>,
    pub(crate) location: Option<String>,
    pub(crate) router_id: Option<String>,
    pub(crate) auto_ip_version: Option<u8>,
    pub(crate) enabled_sav_app: Option<String>,
    pub(crate) apps: Vec<String>,
    pub(crate) prefixes: Vec<String>,
    pub(crate) prefix_count: usize,
    pub(crate) ignore_nets: Vec<String>,
    pub(crate) use_ignore_nets: bool,
    pub(crate) ignore_private: bool,
    pub(crate) data_plane_auto: bool,
    pub(crate) data_plane_dry_run: bool,
    pub(crate) data_plane_interval_ms: u64,
    pub(crate) data_plane_active_app: Option<String>,
    pub(crate) roa_info: BTreeMap<i64, BTreeSet<String>>,
    pub(crate) aspa_info: BTreeMap<i64, BTreeSet<i64>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LinkState {
    pub(crate) protocol_name: String,
    pub(crate) interface_name: String,
    pub(crate) link_type: Option<String>,
    pub(crate) local_ip: Option<String>,
    pub(crate) remote_ip: Option<String>,
    pub(crate) remote_id: Option<String>,
    pub(crate) is_interior: Option<bool>,
    pub(crate) remote_as: Option<u64>,
    pub(crate) local_role: Option<String>,
    pub(crate) remote_role: Option<String>,
    pub(crate) remote_location: Option<String>,
    pub(crate) status: bool,
    pub(crate) events: u64,
    pub(crate) link_state_changes: u64,
    pub(crate) last_seen: Option<f64>,
    pub(crate) last_msg_type: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct EventRecord {
    ts: f64,
    msg_type: String,
    source_link: Option<String>,
    link_type: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct LinkTotals {
    count: usize,
    up: usize,
    down: usize,
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeState {
    config: ConfigSummary,
    links: BTreeMap<String, LinkState>,
    event_counts: BTreeMap<String, u64>,
    total_events: u64,
    last_events: Vec<EventRecord>,
}

#[derive(Clone, Debug, Serialize)]
struct DataPlaneAutoState {
    enabled: bool,
    dry_run: bool,
    active_app: Option<String>,
    interval_ms: u64,
    last_hash: Option<u64>,
    last_check: Option<f64>,
    last_refresh: Option<f64>,
    refresh_count: u64,
    skip_count: u64,
    error_count: u64,
    last_result: Option<DataPlaneApplyResult>,
    last_error: Option<String>,
    phase: String,
    paused: bool,
    consecutive_errors: u32,
    installed_fingerprint: Option<u64>,
    last_verified: Option<f64>,
    dry_run_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct KernelRoute {
    pub(crate) family: u8,
    pub(crate) prefix: String,
    pub(crate) interface_name: Option<String>,
    pub(crate) gateway: Option<String>,
    pub(crate) route_type: Option<String>,
    pub(crate) protocol: Option<String>,
    pub(crate) scope: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BirdRoute {
    pub(crate) prefix: String,
    pub(crate) interface_name: Option<String>,
    pub(crate) as_path: Vec<u64>,
    pub(crate) origin_as: Option<u64>,
    pub(crate) selected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct SavRule {
    pub(crate) prefix: String,
    pub(crate) interface_name: String,
    pub(crate) source_app: String,
    pub(crate) origin: i64,
    pub(crate) is_interior: bool,
}

#[derive(Clone, Debug, Serialize)]
struct DataPlaneApplyResult {
    active_app: String,
    dry_run: bool,
    ipv4_rules: usize,
    ipv6_rules: usize,
    ipv4_commands: usize,
    ipv6_commands: usize,
    interfaces: Vec<String>,
    warnings: Vec<String>,
}

struct DataPlanePlan {
    active_app: String,
    dry_run: bool,
    hash: u64,
    interfaces: Vec<String>,
    ipv4_rules: usize,
    ipv6_rules: usize,
    v4_lines: Vec<String>,
    v6_lines: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BirdRouteCacheStatus {
    dirty: bool,
    route_count: usize,
    last_refresh: Option<f64>,
    refresh_count: u64,
    hit_count: u64,
    error_count: u64,
    last_error: Option<String>,
}

#[derive(Clone, Debug)]
struct BirdRouteCache {
    routes: Vec<BirdRoute>,
    dirty: bool,
    last_refresh: Option<f64>,
    refresh_count: u64,
    hit_count: u64,
    error_count: u64,
    last_error: Option<String>,
}

impl BirdRouteCache {
    fn new() -> Self {
        Self {
            routes: Vec::new(),
            dirty: true,
            last_refresh: None,
            refresh_count: 0,
            hit_count: 0,
            error_count: 0,
            last_error: None,
        }
    }

    fn status(&self) -> BirdRouteCacheStatus {
        BirdRouteCacheStatus {
            dirty: self.dirty,
            route_count: self.routes.len(),
            last_refresh: self.last_refresh,
            refresh_count: self.refresh_count,
            hit_count: self.hit_count,
            error_count: self.error_count,
            last_error: self.last_error.clone(),
        }
    }
}

struct BirdControlClient {
    reader: BufReader<UnixStream>,
}

impl BirdControlClient {
    fn connect(path: &Path, timeout: Duration) -> Result<Self, String> {
        let stream = UnixStream::connect(path)
            .map_err(|err| format!("connect {} failed: {err}", path.display()))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| format!("set BIRD socket read timeout failed: {err}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| format!("set BIRD socket write timeout failed: {err}"))?;
        let mut client = Self {
            reader: BufReader::new(stream),
        };
        let _ = client.read_response()?;
        Ok(client)
    }

    fn command(&mut self, command: &str) -> Result<Vec<String>, String> {
        self.reader
            .get_mut()
            .write_all(command.as_bytes())
            .map_err(|err| format!("write BIRD command failed: {err}"))?;
        self.reader
            .get_mut()
            .write_all(b"\n")
            .map_err(|err| format!("write BIRD command newline failed: {err}"))?;
        self.reader
            .get_mut()
            .flush()
            .map_err(|err| format!("flush BIRD command failed: {err}"))?;
        self.read_response()
    }

    fn read_response(&mut self) -> Result<Vec<String>, String> {
        let mut output = Vec::new();
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|err| format!("read BIRD response failed: {err}"))?;
            if n == 0 {
                return Err("BIRD control socket closed".to_string());
            }
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }

            if let Some(rest) = line.strip_prefix('+') {
                output.push(format!(">>> {rest}"));
                continue;
            }
            if let Some(rest) = line.strip_prefix(' ') {
                output.push(rest.to_string());
                continue;
            }
            if line.len() > 4
                && line.as_bytes()[0..4].iter().all(u8::is_ascii_digit)
                && matches!(line.as_bytes()[4], b' ' | b'-')
            {
                let code: u16 = line[0..4].parse().unwrap_or(9999);
                if code != 0 && line.len() > 5 {
                    output.push(line[5..].to_string());
                }
                if line.as_bytes()[4] == b' ' {
                    return Ok(output);
                }
                continue;
            }
            output.push(line);
        }
    }
}

impl Default for DataPlaneAutoState {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: false,
            active_app: None,
            interval_ms: 1000,
            last_hash: None,
            last_check: None,
            last_refresh: None,
            refresh_count: 0,
            skip_count: 0,
            error_count: 0,
            last_result: None,
            last_error: None,
            phase: "idle".to_string(),
            paused: false,
            consecutive_errors: 0,
            installed_fingerprint: None,
            last_verified: None,
            dry_run_count: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct Prefix {
    addr: IpAddr,
    len: u8,
}

struct Metrics {
    http_requests: AtomicU64,
    bird_uploads: AtomicU64,
    request_cmds: AtomicU64,
    bad_requests: AtomicU64,
    server_started: AtomicBool,
    data_plane_started: AtomicBool,
}

impl Metrics {
    fn new() -> Self {
        Self {
            http_requests: AtomicU64::new(0),
            bird_uploads: AtomicU64::new(0),
            request_cmds: AtomicU64::new(0),
            bad_requests: AtomicU64::new(0),
            server_started: AtomicBool::new(false),
            data_plane_started: AtomicBool::new(false),
        }
    }
}

impl ConfigSummary {
    fn unloaded(path: &Path, err: impl Into<String>) -> Self {
        Self {
            config_loaded: false,
            config_error: Some(err.into()),
            config_path: path.display().to_string(),
            device_id: "unknown".to_string(),
            local_as: None,
            location: None,
            router_id: None,
            auto_ip_version: None,
            enabled_sav_app: None,
            apps: Vec::new(),
            prefixes: Vec::new(),
            prefix_count: 0,
            ignore_nets: Vec::new(),
            use_ignore_nets: false,
            ignore_private: false,
            data_plane_auto: false,
            data_plane_dry_run: false,
            data_plane_interval_ms: 1000,
            data_plane_active_app: None,
            roa_info: BTreeMap::new(),
            aspa_info: BTreeMap::new(),
        }
    }
}

impl RuntimeState {
    fn from_config(path: &Path) -> Self {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                return Self {
                    config: ConfigSummary::unloaded(path, format!("read failed: {err}")),
                    links: BTreeMap::new(),
                    event_counts: BTreeMap::new(),
                    total_events: 0,
                    last_events: Vec::new(),
                };
            }
        };
        let root: Value = match serde_json::from_str(&content) {
            Ok(root) => root,
            Err(err) => {
                return Self {
                    config: ConfigSummary::unloaded(path, format!("parse failed: {err}")),
                    links: BTreeMap::new(),
                    event_counts: BTreeMap::new(),
                    total_events: 0,
                    last_events: Vec::new(),
                };
            }
        };

        let prefixes = object_keys(root.get("prefixes"));
        let local_as = value_u64(&root, "local_as");
        let roa_info = parse_roa_info(&root);
        let aspa_info = parse_aspa_info(&root);
        let data_plane_auto = config_or_env_bool(
            &root,
            &[
                "data_plane_auto",
                "dataplane_auto",
                "auto_data_plane",
                "data_plane_enabled",
                "enable_data_plane",
            ],
            "SAVOP_DATA_PLANE_AUTO",
            false,
        );
        let data_plane_dry_run = config_or_env_bool(
            &root,
            &["data_plane_dry_run", "dataplane_dry_run"],
            "SAVOP_DATA_PLANE_DRY_RUN",
            false,
        );
        let data_plane_interval_ms = config_or_env_u64(
            &root,
            &["data_plane_interval_ms", "dataplane_interval_ms"],
            "SAVOP_DATA_PLANE_INTERVAL_MS",
            1000,
        )
        .max(100);
        let data_plane_active_app = env::var("SAVOP_DATA_PLANE_APP")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| value_string(&root, "data_plane_active_app"))
            .or_else(|| value_string(&root, "dataplane_active_app"));
        let config = ConfigSummary {
            config_loaded: true,
            config_error: None,
            config_path: path.display().to_string(),
            device_id: value_string(&root, "device_id").unwrap_or_else(|| "unknown".to_string()),
            local_as,
            location: value_string(&root, "location"),
            router_id: value_string(&root, "router_id"),
            auto_ip_version: value_u8(&root, "auto_ip_version"),
            enabled_sav_app: value_string(&root, "enabled_sav_app"),
            apps: string_vec(root.get("apps")),
            prefix_count: prefixes.len(),
            prefixes,
            ignore_nets: string_vec(root.get("ignore_nets")),
            use_ignore_nets: value_bool(&root, "use_ignore_nets").unwrap_or(false),
            ignore_private: value_bool(&root, "ignore_private").unwrap_or(false),
            data_plane_auto,
            data_plane_dry_run,
            data_plane_interval_ms,
            data_plane_active_app,
            roa_info,
            aspa_info,
        };

        let mut links = BTreeMap::new();
        if let Some(link_map) = root.get("link_map").and_then(Value::as_object) {
            for (protocol_name, raw) in link_map {
                let remote_id = value_string(raw, "remote_id");
                links.insert(
                    protocol_name.clone(),
                    LinkState {
                        protocol_name: protocol_name.clone(),
                        interface_name: interface_name_for(protocol_name, remote_id.as_deref()),
                        link_type: value_string(raw, "link_type"),
                        local_ip: value_string(raw, "local_ip"),
                        remote_ip: value_string(raw, "remote_ip"),
                        remote_id,
                        is_interior: value_bool(raw, "is_interior"),
                        remote_as: value_u64(raw, "remote_as"),
                        local_role: value_string(raw, "local_role"),
                        remote_role: value_string(raw, "remote_role"),
                        remote_location: value_string(raw, "remote_location"),
                        status: true,
                        events: 0,
                        link_state_changes: 0,
                        last_seen: None,
                        last_msg_type: None,
                    },
                );
            }
        }

        Self {
            config,
            links,
            event_counts: BTreeMap::new(),
            total_events: 0,
            last_events: Vec::new(),
        }
    }

    fn record_event(
        &mut self,
        msg_type: String,
        source_link: Option<String>,
        link_type: Option<String>,
        status: Option<bool>,
    ) {
        self.total_events += 1;
        *self.event_counts.entry(msg_type.clone()).or_insert(0) += 1;

        if let Some(protocol_name) = source_link.as_deref() {
            if let Some(link) = self.links.get_mut(protocol_name) {
                link.events += 1;
                link.last_seen = Some(now_secs());
                link.last_msg_type = Some(msg_type.clone());
                if msg_type == "link_state_change" {
                    link.link_state_changes += 1;
                    if let Some(status) = status {
                        link.status = status;
                    }
                }
            }
        }

        self.last_events.push(EventRecord {
            ts: now_secs(),
            msg_type,
            source_link,
            link_type,
        });
        if self.last_events.len() > 32 {
            let excess = self.last_events.len() - 32;
            self.last_events.drain(0..excess);
        }
    }

    fn link_totals(&self) -> LinkTotals {
        let count = self.links.len();
        let up = self.links.values().filter(|link| link.status).count();
        LinkTotals {
            count,
            up,
            down: count.saturating_sub(up),
        }
    }
}

#[derive(Clone)]
struct Agent {
    cfg: Config,
    metrics: Arc<Metrics>,
    state: Arc<Mutex<RuntimeState>>,
    data_plane: Arc<Mutex<DataPlaneAutoState>>,
    bird_route_cache: Arc<Mutex<BirdRouteCache>>,
    active_sav_app: Arc<Mutex<Option<String>>>,
    urpf_caches: Arc<Mutex<sav_apps::urpf_cache::UrpfCaches>>,
    // Serialize snapshot/build/install with manual selection, disable and stop.
    data_plane_operation: Arc<Mutex<()>>,
}

fn env_path(name: &str, default: PathBuf) -> PathBuf {
    env::var_os(name).map(PathBuf::from).unwrap_or(default)
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs_f64()
}

fn now_string() -> String {
    format!("{:.3}", now_secs())
}

const NFT_TABLE: &str = "savop";
const NFT_CHAIN: &str = "savagent";

fn prefix_family(prefix: &str) -> Option<u8> {
    match parse_prefix(prefix)?.addr {
        IpAddr::V4(_) => Some(4),
        IpAddr::V6(_) => Some(6),
    }
}

fn get_data_plane_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return interfaces;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo"
            || name.starts_with("docker")
            || name.starts_with("br-")
            || name.starts_with("ifb")
        {
            continue;
        }
        interfaces.push(name);
    }
    interfaces.sort();
    interfaces
}

mod urpf_dataplane;

fn build_nft_family_lines(
    active_app: &str,
    family: u8,
    rules: &[&SavRule],
    links: &BTreeMap<String, LinkState>,
) -> Result<Vec<String>, String> {
    if matches!(active_app, "strict_urpf" | "loose_urpf") {
        urpf_dataplane::compile(active_app, family, rules, links)
    } else if is_efp_app(active_app) {
        Ok(build_efp_nft_lines(family, rules, links))
    } else {
        Ok(build_blacklist_nft_lines(family, rules))
    }
}

fn data_plane_plan_hash(
    active_app: &str,
    v4_rules: &[&SavRule],
    v6_rules: &[&SavRule],
    v4_lines: &[String],
    v6_lines: &[String],
) -> u64 {
    let mut hasher = DefaultHasher::new();
    active_app.hash(&mut hasher);
    v4_rules.hash(&mut hasher);
    v6_rules.hash(&mut hasher);
    v4_lines.hash(&mut hasher);
    v6_lines.hash(&mut hasher);
    hasher.finish()
}

fn is_efp_app(active_app: &str) -> bool {
    active_app.starts_with("efp_urpf_a") || active_app.starts_with("efp_urpf_b")
}

fn build_blacklist_nft_lines(family: u8, rules: &[&SavRule]) -> Vec<String> {
    let Some((addr_type, addr_expr, known_set, allow_set)) = nft_family_names(family) else {
        return Vec::new();
    };
    let mut allow_by_prefix: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut wildcard_prefixes = BTreeSet::new();
    for rule in rules {
        if rule.interface_name == "*" {
            wildcard_prefixes.insert(rule.prefix.clone());
            continue;
        }
        allow_by_prefix
            .entry(rule.prefix.clone())
            .or_default()
            .insert(rule.interface_name.clone());
    }

    let mut known_prefixes = Vec::new();
    let mut prefixes_by_interface: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (prefix, allowed_interfaces) in allow_by_prefix {
        if wildcard_prefixes.contains(&prefix) {
            continue;
        }
        known_prefixes.push(prefix.clone());
        for interface_name in allowed_interfaces {
            prefixes_by_interface
                .entry(interface_name)
                .or_default()
                .push(prefix.clone());
        }
    }
    known_prefixes = compact_prefixes(known_prefixes);
    let mut allow_elements = Vec::new();
    for (interface_name, prefixes) in prefixes_by_interface {
        for prefix in compact_prefixes(prefixes) {
            allow_elements.push(format!("{prefix} . {}", nft_string(&interface_name)));
        }
    }

    let mut lines = Vec::new();
    if known_prefixes.is_empty() {
        return lines;
    }
    lines.push(format!(
        "add set inet {NFT_TABLE} {known_set} {{ type {addr_type}; flags interval; auto-merge; }}"
    ));
    lines.push(format!(
        "add set inet {NFT_TABLE} {allow_set} {{ type {addr_type} . ifname; flags interval; }}"
    ));
    push_nft_element_chunks(&mut lines, known_set, &known_prefixes);
    push_nft_element_chunks(&mut lines, allow_set, &allow_elements);
    lines.push(format!(
        "add rule inet {NFT_TABLE} {NFT_CHAIN} {addr_expr} @{known_set} {addr_expr} . iifname != @{allow_set} drop"
    ));
    lines
}

fn build_efp_nft_lines(
    family: u8,
    rules: &[&SavRule],
    links: &BTreeMap<String, LinkState>,
) -> Vec<String> {
    let Some((addr_type, addr_expr, _, allow_set)) = nft_family_names(family) else {
        return Vec::new();
    };
    let mut prefixes_by_interface: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rule in rules {
        if rule.interface_name != "*" {
            prefixes_by_interface
                .entry(rule.interface_name.clone())
                .or_default()
                .push(rule.prefix.clone());
        }
    }
    let mut allow_elements = Vec::new();
    for (interface_name, prefixes) in prefixes_by_interface {
        for prefix in compact_prefixes(prefixes) {
            allow_elements.push(format!("{prefix} . {}", nft_string(&interface_name)));
        }
    }
    let mut lines = Vec::new();
    if !allow_elements.is_empty() {
        lines.push(format!(
            "add set inet {NFT_TABLE} {allow_set} {{ type {addr_type} . ifname; flags interval; }}"
        ));
        push_nft_element_chunks(&mut lines, allow_set, &allow_elements);
        lines.push(format!(
            "add rule inet {NFT_TABLE} {NFT_CHAIN} {addr_expr} . iifname @{allow_set} accept"
        ));
    }
    for interface_name in provider_interfaces(links) {
        lines.push(format!(
            "add rule inet {NFT_TABLE} {NFT_CHAIN} iifname {} udp drop",
            nft_string(&interface_name)
        ));
    }
    lines
}

fn nft_family_names(
    family: u8,
) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match family {
        4 => Some(("ipv4_addr", "ip saddr", "sav_known4", "sav_allow4")),
        6 => Some(("ipv6_addr", "ip6 saddr", "sav_known6", "sav_allow6")),
        _ => None,
    }
}

fn push_nft_element_chunks(lines: &mut Vec<String>, set_name: &str, elements: &[String]) {
    for chunk in elements.chunks(512) {
        lines.push(format!(
            "add element inet {NFT_TABLE} {set_name} {{ {} }}",
            chunk.join(", ")
        ));
    }
}

fn nft_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn compact_prefixes(prefixes: Vec<String>) -> Vec<String> {
    let mut parsed: Vec<Prefix> = prefixes
        .into_iter()
        .filter_map(|prefix| parse_prefix(&prefix))
        .collect();
    parsed.sort_by_key(|prefix| {
        let family = match prefix.addr {
            IpAddr::V4(_) => 4_u8,
            IpAddr::V6(_) => 6_u8,
        };
        (family, prefix.len, prefix.addr.to_string())
    });

    let mut kept: Vec<Prefix> = Vec::new();
    'candidate: for prefix in parsed {
        for existing in &kept {
            if prefix_contains(existing, &prefix) {
                continue 'candidate;
            }
        }
        kept.push(prefix);
    }

    kept.into_iter()
        .map(|prefix| format!("{}/{}", prefix.addr, prefix.len).to_ascii_lowercase())
        .collect()
}

fn provider_interfaces(links: &BTreeMap<String, LinkState>) -> BTreeSet<String> {
    links
        .values()
        .filter(|link| {
            link.remote_role.as_deref() == Some("provider")
                || link.local_role.as_deref() == Some("customer")
        })
        .map(|link| link.interface_name.clone())
        .collect()
}

fn apply_nft_lines(lines: &[String], log_path: &Path, hash: u64) -> Result<(), String> {
    let mut body = [
        // One nft transaction, including deletion. An invalid replacement must
        // leave the prior rules active. add is idempotent; delete also clears
        // named sets (flush table alone would retain stale elements).
        format!("add table inet {NFT_TABLE}"),
        format!("delete table inet {NFT_TABLE}"),
        format!("add table inet {NFT_TABLE} {{ comment \"savop-plan-{hash:016x}\"; }}"),
        format!(
            "add chain inet {NFT_TABLE} {NFT_CHAIN}_input {{ type filter hook input priority 0; policy accept; }}"
        ),
        format!(
            "add chain inet {NFT_TABLE} {NFT_CHAIN}_forward {{ type filter hook forward priority 0; policy accept; }}"
        ),
        format!("add chain inet {NFT_TABLE} {NFT_CHAIN} {{ }}"),
        format!("add rule inet {NFT_TABLE} {NFT_CHAIN}_input jump {NFT_CHAIN}"),
        format!("add rule inet {NFT_TABLE} {NFT_CHAIN}_forward jump {NFT_CHAIN}"),
    ]
    .join("\n");
    body.push('\n');
    for line in lines {
        body.push_str(line);
        body.push('\n');
    }
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create log dir failed: {err}"))?;
    }
    fs::write(log_path, &body).map_err(|err| format!("write nft file failed: {err}"))?;

    // File input avoids a blocked stdin writer when nft itself stalls.
    let output = auto_dataplane::run_command(
        Command::new("nft").arg("-f").arg(log_path),
        auto_dataplane::command_timeout(),
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn delete_nft_table() -> Result<(), String> {
    let output = auto_dataplane::run_command(
        Command::new("nft").args(["delete", "table", "inet", NFT_TABLE]),
        auto_dataplane::command_timeout(),
    )?;
    if output.status.success() || String::from_utf8_lossy(&output.stderr).contains("No such file") {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

impl Config {
    fn from_env() -> Self {
        let data_path = env_path("SAVOP_DATA_PATH", PathBuf::from("/root/savop"));
        let config_path = env_path("SAVOP_CONFIG_PATH", data_path.join("SavAgent_config.json"));
        let signal_path = env_path("SAVOP_SIGNAL_PATH", data_path.join("signal.json"));
        let log_dir = env_path("SAVOP_LOG_DIR", data_path.join("logs"));
        let bird_pid_file = env::var_os("SAVOP_BIRD_PID_FILE").map(PathBuf::from);
        Self {
            exec_results_path: log_dir.join("exec_results.json"),
            bird_logfile: log_dir.join("bird.log"),
            bird_bin: env::var("SAVOP_BIRD_BIN").unwrap_or_else(|_| "bird".to_string()),
            bird_config: env::var("SAVOP_BIRD_CONFIG")
                .unwrap_or_else(|_| "/usr/local/etc/bird.conf".to_string()),
            bird_socket: env_path(
                "SAVOP_BIRD_SOCKET",
                PathBuf::from("/usr/local/var/run/bird.ctl"),
            ),
            listen_addr: env::var("SAVOP_AGENT_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8888".to_string()),
            data_path,
            config_path,
            signal_path,
            log_dir,
            bird_pid_file,
        }
    }
}

impl Agent {
    fn new() -> std::io::Result<Self> {
        let cfg = Config::from_env();
        fs::create_dir_all(&cfg.log_dir)?;
        let state = RuntimeState::from_config(&cfg.config_path);
        Ok(Self {
            cfg,
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(Mutex::new(state)),
            data_plane: Arc::new(Mutex::new(DataPlaneAutoState::default())),
            bird_route_cache: Arc::new(Mutex::new(BirdRouteCache::new())),
            active_sav_app: Arc::new(Mutex::new(None)),
            urpf_caches: Arc::new(Mutex::new(sav_apps::urpf_cache::UrpfCaches::default())),
            data_plane_operation: Arc::new(Mutex::new(())),
        })
    }

    fn log(&self, message: &str) {
        let _ = fs::create_dir_all(&self.cfg.log_dir);
        let path = self.cfg.log_dir.join("sav_agent.log");
        if let Ok(mut fh) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(fh, "[{}] {}", now_string(), message);
        }
    }

    fn reload_config(&self) {
        let Ok(_operation) = self.data_plane_operation.lock() else {
            return;
        };
        let new_state = RuntimeState::from_config(&self.cfg.config_path);
        let loaded = new_state.config.config_loaded;
        let err = new_state.config.config_error.clone();
        if let Ok(mut state) = self.state.lock() {
            *state = new_state;
        }
        self.mark_bird_route_cache_dirty();
        self.reconcile_runtime_active_sav_app();
        if loaded {
            self.log(&format!("loaded config {}", self.cfg.config_path.display()));
        } else if let Some(err) = err {
            self.log(&format!(
                "failed to load config {}: {}",
                self.cfg.config_path.display(),
                err
            ));
        }
    }

    fn mark_bird_route_cache_dirty(&self) {
        if let Ok(mut cache) = self.bird_route_cache.lock() {
            cache.dirty = true;
        }
    }

    fn bird_route_cache_status(&self) -> Option<BirdRouteCacheStatus> {
        self.bird_route_cache
            .lock()
            .ok()
            .map(|cache| cache.status())
    }

    fn configured_active_sav_app(config: &ConfigSummary) -> Option<String> {
        config
            .data_plane_active_app
            .clone()
            .or_else(|| config.enabled_sav_app.clone())
            .filter(|value| !value.trim().is_empty())
    }

    fn runtime_active_sav_app(&self) -> Option<String> {
        self.active_sav_app
            .lock()
            .ok()
            .and_then(|active| active.clone())
            .filter(|value| !value.trim().is_empty())
    }

    fn selected_active_sav_app(&self, config: &ConfigSummary) -> Option<String> {
        self.runtime_active_sav_app()
            .or_else(|| Self::configured_active_sav_app(config))
    }

    fn available_sav_apps(config: &ConfigSummary) -> Vec<String> {
        sav_apps::active_app_ids(&config.apps)
            .into_iter()
            .filter(|app| sav_apps::is_known_app_id(app))
            .collect()
    }

    fn sav_app_selection_for_config(&self, config: &ConfigSummary) -> Value {
        let runtime_active_app = self.runtime_active_sav_app();
        let configured_active_app = Self::configured_active_sav_app(config);
        let selected_active_app = runtime_active_app
            .clone()
            .or_else(|| configured_active_app.clone());
        json!({
            "runtime_active_app": runtime_active_app,
            "configured_active_app": configured_active_app,
            "selected_active_app": selected_active_app,
            "available_apps": Self::available_sav_apps(config)
        })
    }

    fn sav_app_selection_json(&self) -> String {
        match self.state.lock() {
            Ok(state) => json!({
                "code": "0000",
                "data": self.sav_app_selection_for_config(&state.config)
            })
            .to_string(),
            Err(_) => json!({"code":"5004","message":"state_lock_poisoned"}).to_string(),
        }
    }

    fn set_runtime_active_sav_app(&self, active_app: Option<String>) {
        if let Ok(mut current) = self.active_sav_app.lock() {
            *current = active_app;
        }
    }

    fn reconcile_runtime_active_sav_app(&self) {
        let Some(active_app) = self.runtime_active_sav_app() else {
            return;
        };
        let keep = self
            .state
            .lock()
            .ok()
            .map(|state| {
                sav_apps::is_known_app_id(&active_app)
                    && Self::available_sav_apps(&state.config).contains(&active_app)
            })
            .unwrap_or(false);
        if !keep {
            self.set_runtime_active_sav_app(None);
        }
    }

    fn run_sysctl(&self, setting: &str) {
        let _ = Command::new("sysctl")
            .arg("-w")
            .arg(setting)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn system_check(&self) {
        for setting in [
            "net.ipv4.conf.all.rp_filter=0",
            "net.ipv4.conf.default.rp_filter=0",
            "net.ipv4.conf.default.accept_local=1",
            "net.ipv4.conf.all.accept_local=1",
            "net.ipv4.ip_forward=1",
            "net.ipv6.conf.all.forwarding=1",
            "net.ipv4.tcp_fin_timeout=1",
            "net.ipv4.tcp_tw_reuse=1",
            "fs.file-max=1000000",
            "net.ipv4.tcp_max_syn_backlog=1000000",
            "net.core.somaxconn=1000000",
            "net.ipv4.tcp_max_tw_buckets=1000000",
            "net.ipv4.tcp_max_orphans=1000000",
            "net.ipv4.tcp_syncookies=1",
        ] {
            self.run_sysctl(setting);
        }
    }

    fn parse_signal(content: &str) -> Option<&'static str> {
        if !content.contains("\"command\"") {
            return None;
        }
        if content.contains("\"start\"") {
            Some("start")
        } else if content.contains("\"stop\"") {
            Some("stop")
        } else {
            None
        }
    }

    fn bird_pid(&self) -> Option<i32> {
        let path = self.cfg.bird_pid_file.as_ref()?;
        fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    fn proc_exists(pid: i32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    fn kill_pid_file(&self) {
        let Some(path) = self.cfg.bird_pid_file.as_ref() else {
            return;
        };
        let Some(pid) = self.bird_pid() else {
            let _ = fs::remove_file(path);
            return;
        };

        let _ = Command::new("kill")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        for _ in 0..20 {
            if !Self::proc_exists(pid) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if Self::proc_exists(pid) {
            let _ = Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        let _ = fs::remove_file(path);
    }

    fn stop_bird(&self) {
        if self.cfg.bird_pid_file.is_some() {
            self.kill_pid_file();
        } else {
            let _ = Command::new("pkill")
                .args(["-9", "-x", "bird"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    fn start_bird(&self) -> std::io::Result<()> {
        self.stop_bird();
        let _ = fs::remove_file(&self.cfg.bird_socket);
        let _ = fs::remove_file(&self.cfg.bird_logfile);

        let mut cmd = Command::new(&self.cfg.bird_bin);
        cmd.arg("-c")
            .arg(&self.cfg.bird_config)
            .arg("-s")
            .arg(&self.cfg.bird_socket)
            .arg("-D")
            .arg(&self.cfg.bird_logfile);
        if let Some(pid_file) = &self.cfg.bird_pid_file {
            cmd.arg("-P").arg(pid_file);
        }
        let status = cmd.status()?;
        if !status.success() {
            self.log(&format!("bird exited with status {status}"));
        }
        Ok(())
    }

    fn write_exec_result(&self, action: &str, result: &str) {
        let body = format!(
            "{{\n  \"command\": \"{}_{}\",\n  \"execute_start_time\": \"{}\",\n  \"cmd_exe_dt\": {},\n  \"action\": \"{}\",\n  \"execute_end_time\": \"{}\",\n  \"execute_result\": \"{}\",\n  \"mode\": \"rust-thin\"\n}}\n",
            action,
            now_string(),
            now_string(),
            now_secs(),
            action,
            now_string(),
            json_escape(result)
        );
        let _ = fs::write(&self.cfg.exec_results_path, body);
    }

    fn start(&self) {
        self.reload_config();
        self.start_http_server_once();
        match self.start_bird() {
            Ok(_) => {
                if let Ok(_operation) = self.data_plane_operation.lock() {
                    self.resume_data_plane();
                }
                self.start_data_plane_auto_once();
                self.mark_bird_route_cache_dirty();
                self.log("bird started");
                self.write_exec_result("start", "ok");
            }
            Err(err) => {
                self.log(&format!("start_bird failed: {err}"));
                self.write_exec_result("start", &format!("error: {err}"));
            }
        }
    }

    fn stop(&self) {
        let result = self.pause_and_remove_data_plane();
        self.stop_bird();
        match result {
            Ok(()) => self.write_exec_result("stop", "ok"),
            Err(error) => self.write_exec_result("stop", &format!("error: {error}")),
        }
    }

    fn start_http_server_once(&self) {
        if self.metrics.server_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let agent = self.clone();
        thread::spawn(move || {
            if let Err(err) = agent.http_server() {
                agent.log(&format!("http server stopped: {err}"));
                agent.metrics.server_started.store(false, Ordering::SeqCst);
            }
        });
        for _ in 0..200 {
            if TcpStream::connect("127.0.0.1:8888").is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.log("http server did not become ready within timeout");
    }

    fn start_data_plane_auto_once(&self) {
        if self.metrics.data_plane_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let agent = self.clone();
        thread::spawn(move || agent.data_plane_auto_loop());
    }

    fn data_plane_auto_loop(&self) {
        loop {
            let delay = self.reconcile_data_plane();
            thread::sleep(Duration::from_millis(delay));
        }
    }

    fn data_plane_auto_config(&self) -> (bool, bool, Option<String>, u64) {
        match self.state.lock() {
            Ok(state) => {
                let config = &state.config;
                let active_app = self.selected_active_sav_app(config);
                (
                    config.data_plane_auto,
                    config.data_plane_dry_run,
                    active_app,
                    config.data_plane_interval_ms,
                )
            }
            Err(_) => (false, false, None, 1000),
        }
    }

    fn http_server(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.cfg.listen_addr)?;
        self.log(&format!(
            "http server listening on {}",
            self.cfg.listen_addr
        ));
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let agent = self.clone();
                    thread::spawn(move || agent.handle_stream(stream));
                }
                Err(err) => self.log(&format!("accept failed: {err}")),
            }
        }
        Ok(())
    }

    fn handle_stream(&self, mut stream: TcpStream) {
        self.metrics.http_requests.fetch_add(1, Ordering::Relaxed);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut data = Vec::with_capacity(4096);
        let mut buf = [0_u8; 4096];
        let header_end;

        loop {
            match stream.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = find_subslice(&data, b"\r\n\r\n") {
                        header_end = pos + 4;
                        break;
                    }
                    if data.len() > 1024 * 1024 {
                        self.metrics.bad_requests.fetch_add(1, Ordering::Relaxed);
                        write_response(&mut stream, "413 Payload Too Large", "{\"code\":\"413\"}");
                        return;
                    }
                }
                Err(_) => return,
            }
        }

        let header = String::from_utf8_lossy(&data[..header_end]).to_string();
        let content_len = parse_content_length(&header).unwrap_or(0);
        while data.len() < header_end + content_len {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        let body = String::from_utf8_lossy(&data[header_end..]).to_string();
        let first_line = header.lines().next().unwrap_or("");
        let path = first_line.split_whitespace().nth(1).unwrap_or("/");
        let response = self.handle_request(path, &body);
        write_response(&mut stream, "200 OK", &response);
    }

    fn handle_request(&self, path: &str, body: &str) -> String {
        let path_only = path.split('?').next().unwrap_or(path);
        match path_only {
            "/bird_bgp_upload/" | "/bird_bgp_upload" => self.handle_bird_upload(body),
            "/metric/" | "/metric" => self.metric_json(),
            "/data_plane/" | "/data_plane" | "/data_plane_state/" | "/data_plane_state" => {
                self.data_plane_json()
            }
            "/links/" | "/links" | "/link_state/" | "/link_state" => self.links_json(),
            "/state/" | "/state" => self.state_json(),
            "/sav_table/" | "/sav_table" => self.sav_table_json(),
            "/active_sav_table/" | "/active_sav_table" | "/sav_table/active/"
            | "/sav_table/active" => self.active_sav_table_json(),
            "/save_sav_table/" | "/save_sav_table" => self.save_sav_table_json(),
            "/sav_app/" | "/sav_app" | "/active_sav_app/" | "/active_sav_app" => {
                self.sav_app_selection_json()
            }
            "/switch_sav_app/" | "/switch_sav_app" => self.switch_sav_app_json(body),
            "/enable_sav_table/"
            | "/enable_sav_table"
            | "/install_sav_table/"
            | "/install_sav_table" => self.enable_sav_table_json(body, false),
            "/dry_run_sav_table/" | "/dry_run_sav_table" => self.enable_sav_table_json(body, true),
            "/disable_sav_table/" | "/disable_sav_table" => self.disable_sav_table_json(),
            _ => "{\"code\":\"0000\",\"message\":\"received\"}".to_string(),
        }
    }

    fn handle_bird_upload(&self, body: &str) -> String {
        self.metrics.bird_uploads.fetch_add(1, Ordering::Relaxed);
        let payload: Value = match serde_json::from_str(body) {
            Ok(payload) => payload,
            Err(err) => {
                self.metrics.bad_requests.fetch_add(1, Ordering::Relaxed);
                self.log(&format!("invalid bird upload json: {err}"));
                return json!({"code":"0000","message":"success","warning":"invalid_json"})
                    .to_string();
            }
        };

        let msg_type = value_string(&payload, "msg_type").unwrap_or_else(|| "unknown".to_string());
        if msg_type == "request_cmd" {
            self.metrics.request_cmds.fetch_add(1, Ordering::Relaxed);
            return json!({"code":"0000","message":"success"}).to_string();
        }

        let source_link = extract_protocol_name(&payload, &msg_type);
        let link_type = extract_link_type(&payload, &msg_type);
        let status = if msg_type == "link_state_change" {
            extract_status(&payload)
        } else {
            None
        };

        if let Ok(mut state) = self.state.lock() {
            state.record_event(msg_type, source_link, link_type, status);
        }
        self.mark_bird_route_cache_dirty();
        json!({"code":"0000","message":"success"}).to_string()
    }

    fn metric_json(&self) -> String {
        let data_plane = self.data_plane.lock().ok().map(|state| state.clone());
        let bird_route_cache = self.bird_route_cache_status();
        match self.state.lock() {
            Ok(state) => json!({
                "agent": {
                    "mode": "rust-stateful-mvp",
                    "http_requests": self.metrics.http_requests.load(Ordering::Relaxed),
                    "bird_uploads": self.metrics.bird_uploads.load(Ordering::Relaxed),
                    "request_cmds": self.metrics.request_cmds.load(Ordering::Relaxed),
                    "bad_requests": self.metrics.bad_requests.load(Ordering::Relaxed),
                    "data_path": self.cfg.data_path.display().to_string(),
                    "config_path": self.cfg.config_path.display().to_string()
                },
                "config": &state.config,
                "links": state.link_totals(),
                "events": {
                    "total": state.total_events,
                    "by_type": &state.event_counts
                },
                "sav_app": self.sav_app_selection_for_config(&state.config),
                "data_plane": data_plane,
                "bird_route_cache": bird_route_cache
            })
            .to_string(),
            Err(_) => json!({"agent":{"mode":"rust-stateful-mvp"},"error":"state_lock_poisoned"})
                .to_string(),
        }
    }

    fn data_plane_json(&self) -> String {
        let data_plane = match self.data_plane.lock() {
            Ok(state) => state.clone(),
            Err(_) => {
                return json!({"code":"5004","message":"data_plane_lock_poisoned"}).to_string()
            }
        };
        match self.state.lock() {
            Ok(state) => json!({
                "code": "0000",
                "data": {
                    "sav_app": self.sav_app_selection_for_config(&state.config),
                    "data_plane": data_plane
                }
            })
            .to_string(),
            Err(_) => json!({"code":"5004","message":"state_lock_poisoned"}).to_string(),
        }
    }

    fn links_json(&self) -> String {
        match self.state.lock() {
            Ok(state) => json!({
                "config": {
                    "device_id": &state.config.device_id,
                    "local_as": state.config.local_as
                },
                "totals": state.link_totals(),
                "links": &state.links
            })
            .to_string(),
            Err(_) => json!({"error":"state_lock_poisoned"}).to_string(),
        }
    }

    fn state_json(&self) -> String {
        match self.state.lock() {
            Ok(state) => json!({
                "agent": {
                    "mode": "rust-stateful-mvp",
                    "http_requests": self.metrics.http_requests.load(Ordering::Relaxed),
                    "bird_uploads": self.metrics.bird_uploads.load(Ordering::Relaxed),
                    "request_cmds": self.metrics.request_cmds.load(Ordering::Relaxed),
                    "bad_requests": self.metrics.bad_requests.load(Ordering::Relaxed),
                },
                "state": &*state
            })
            .to_string(),
            Err(_) => json!({"error":"state_lock_poisoned"}).to_string(),
        }
    }

    fn sav_table_json(&self) -> String {
        let table = self.generate_sav_table();
        json!(table).to_string()
    }

    fn active_sav_table_json(&self) -> String {
        let active_app = match self.state.lock() {
            Ok(state) => self.selected_active_sav_app(&state.config),
            Err(_) => None,
        };
        let Some(active_app) = active_app else {
            return json!({"code":"5004","message":"no active SAV app selected"}).to_string();
        };
        self.with_sav_rules_for_app(&active_app, |rules| {
            json!({
                "code": "0000",
                "data": {
                    "active_app": active_app,
                    "rules": rules
                }
            })
            .to_string()
        })
    }

    fn save_sav_table_json(&self) -> String {
        let table = self.generate_sav_table();
        let mut keys_by_app = BTreeMap::new();
        for (app, rules) in table {
            keys_by_app.insert(app, rules.keys().cloned().collect::<Vec<_>>());
        }
        let path = self.cfg.log_dir.join("sav_table.json");
        let body =
            serde_json::to_string_pretty(&keys_by_app).unwrap_or_else(|_| "{}".to_string()) + "\n";
        if let Err(err) = fs::write(&path, body) {
            self.log(&format!("failed to save sav table: {err}"));
        }
        json!(path.display().to_string()).to_string()
    }

    fn enable_sav_table_json(&self, body: &str, force_dry_run: bool) -> String {
        match self.apply_sav_table(body, force_dry_run) {
            Ok(result) => json!({
                "code": "0000",
                "message": if result.dry_run { "dry_run" } else { "installed" },
                "data": result
            })
            .to_string(),
            Err(err) => json!({
                "code": "5004",
                "message": err
            })
            .to_string(),
        }
    }

    fn disable_sav_table_json(&self) -> String {
        match self.pause_and_remove_data_plane() {
            Ok(()) => json!({"code":"0000","message":"disabled","paused":true}).to_string(),
            Err(err) => json!({"code":"5004","message":err,"paused":true}).to_string(),
        }
    }

    fn switch_sav_app_json(&self, body: &str) -> String {
        match self.switch_sav_app(body) {
            Ok((message, data)) => json!({
                "code": "0000",
                "message": message,
                "data": data
            })
            .to_string(),
            Err(err) => json!({
                "code": "5004",
                "message": err
            })
            .to_string(),
        }
    }

    fn switch_sav_app(&self, body: &str) -> Result<(&'static str, Value), String> {
        let _operation = self
            .data_plane_operation
            .lock()
            .map_err(|_| "operation_lock_poisoned")?;
        let request = auto_dataplane::checked_request(body)?;
        let active_app = request
            .as_ref()
            .and_then(|value| {
                value_string(value, "active_app").or_else(|| value_string(value, "app"))
            })
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "active_app is required".to_string())?;
        let dry_run = request
            .as_ref()
            .and_then(|value| value_bool(value, "dry_run"))
            .unwrap_or(false);
        let install = request
            .as_ref()
            .and_then(|value| value_bool(value, "install"))
            .unwrap_or(!dry_run);

        self.validate_sav_app_available(&active_app)?;

        if dry_run {
            let result =
                self.apply_data_plane_plan(self.build_data_plane_plan(&active_app, true)?)?;
            return Ok((
                "dry_run",
                json!({
                    "active_app": active_app,
                    "installed": false,
                    "selected": false,
                    "data_plane": result
                }),
            ));
        }

        if !install {
            self.set_runtime_active_sav_app(Some(active_app.clone()));
            let selection = match self.state.lock() {
                Ok(state) => self.sav_app_selection_for_config(&state.config),
                Err(_) => json!({ "selected_active_app": active_app }),
            };
            return Ok((
                "selected",
                json!({
                    "active_app": active_app,
                    "installed": false,
                    "selected": true,
                    "selection": selection
                }),
            ));
        }

        let result = self.apply_data_plane_plan(self.build_data_plane_plan(&active_app, false)?)?;
        self.set_runtime_active_sav_app(Some(active_app.clone()));
        self.resume_data_plane();
        Ok((
            "installed",
            json!({
                "active_app": active_app,
                "installed": true,
                "selected": true,
                "data_plane": result
            }),
        ))
    }

    fn apply_sav_table(
        &self,
        body: &str,
        force_dry_run: bool,
    ) -> Result<DataPlaneApplyResult, String> {
        let _operation = self
            .data_plane_operation
            .lock()
            .map_err(|_| "operation_lock_poisoned")?;
        let request = auto_dataplane::checked_request(body)?;
        let dry_run = force_dry_run
            || request
                .as_ref()
                .and_then(|v| value_bool(v, "dry_run"))
                .unwrap_or(false);
        let active_app = request
            .as_ref()
            .and_then(|value| {
                value_string(value, "active_app").or_else(|| value_string(value, "app"))
            })
            .or_else(|| {
                self.state
                    .lock()
                    .ok()
                    .and_then(|state| self.selected_active_sav_app(&state.config))
            })
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                "active_app is required when no runtime/configured SAV app is selected".to_string()
            })?;

        let plan = self.build_data_plane_plan(&active_app, dry_run)?;
        let result = self.apply_data_plane_plan(plan)?;
        if !result.dry_run {
            self.set_runtime_active_sav_app(Some(active_app));
            self.resume_data_plane();
        }
        Ok(result)
    }

    fn validate_sav_app_available(&self, active_app: &str) -> Result<(), String> {
        if !sav_apps::is_known_app_id(active_app) {
            return Err(format!("unknown sav_app {active_app}"));
        }
        let available = self
            .state
            .lock()
            .map_err(|_| "state lock poisoned".to_string())
            .map(|state| Self::available_sav_apps(&state.config))?;
        if !available.iter().any(|app| app == active_app) {
            return Err(format!(
                "active_app {active_app} is not enabled in this node config; available: {}",
                available.join(",")
            ));
        }
        Ok(())
    }

    fn build_data_plane_plan(
        &self,
        active_app: &str,
        dry_run: bool,
    ) -> Result<DataPlanePlan, String> {
        self.validate_sav_app_available(active_app)?;
        self.with_checked_sav_rules(active_app, |rules| {
            let interfaces = get_data_plane_interfaces();
            let links = self
                .state
                .lock()
                .map_err(|_| "state lock poisoned".to_string())?
                .links
                .clone();

            let (v4_rules, v6_rules): (Vec<&SavRule>, Vec<&SavRule>) = rules
                .values()
                .partition(|rule| prefix_family(&rule.prefix) == Some(4));
            let v6_rules: Vec<&SavRule> = v6_rules
                .into_iter()
                .filter(|rule| prefix_family(&rule.prefix) == Some(6))
                .collect();

            if matches!(active_app, "strict_urpf" | "loose_urpf") && links.is_empty() {
                return Err("uRPF installation requires explicit configured link scope".into());
            }
            let v4_lines = build_nft_family_lines(active_app, 4, &v4_rules, &links)?;
            let v6_lines = build_nft_family_lines(active_app, 6, &v6_rules, &links)?;

            let mut warnings = Vec::new();
            if interfaces.is_empty() {
                warnings.push("no data-plane interfaces found".to_string());
            }
            let hash = data_plane_plan_hash(active_app, &v4_rules, &v6_rules, &v4_lines, &v6_lines);

            Ok(DataPlanePlan {
                active_app: active_app.to_string(),
                dry_run,
                hash,
                interfaces,
                ipv4_rules: v4_rules.len(),
                ipv6_rules: v6_rules.len(),
                v4_lines,
                v6_lines,
                warnings,
            })
        })
    }

    fn apply_data_plane_plan(&self, plan: DataPlanePlan) -> Result<DataPlaneApplyResult, String> {
        if !plan.dry_run {
            let mut nft_lines = plan.v4_lines.clone();
            nft_lines.extend(plan.v6_lines.iter().cloned());
            apply_nft_lines(
                &nft_lines,
                &self.cfg.log_dir.join("savagent_nftables.rules"),
                plan.hash,
            )
            .map_err(|err| format!("nftables apply failed: {err}"))?;
        }

        let fingerprint = if plan.dry_run {
            None
        } else {
            Some(
                auto_dataplane::installed_fingerprint(Some(plan.hash))?
                    .ok_or("nft table missing after install")?,
            )
        };
        let result = DataPlaneApplyResult {
            active_app: plan.active_app,
            dry_run: plan.dry_run,
            ipv4_rules: plan.ipv4_rules,
            ipv6_rules: plan.ipv6_rules,
            ipv4_commands: plan.v4_lines.len(),
            ipv6_commands: plan.v6_lines.len(),
            interfaces: plan.interfaces,
            warnings: plan.warnings,
        };
        let mut status = self
            .data_plane
            .lock()
            .map_err(|_| "data_plane_lock_poisoned")?;
        if !result.dry_run {
            status.last_hash = Some(plan.hash);
            status.installed_fingerprint = fingerprint;
            status.last_verified = Some(now_secs());
            status.last_refresh = Some(now_secs());
            status.refresh_count += 1;
            status.last_result = Some(result.clone());
            status.phase = "applied".to_string();
            status.last_error = None;
            status.consecutive_errors = 0;
        } else {
            // A preview must never suppress a later real installation.
            status.dry_run_count += 1;
        }
        Ok(result)
    }

    fn generate_sav_table(&self) -> sav_apps::SavTable {
        // Serialize snapshot acquisition and cache mutation to prevent older
        // concurrent snapshots from overwriting newer cache state.
        let mut caches = self.urpf_caches.lock().ok();
        let (config, links) = match self.state.lock() {
            Ok(state) => (state.config.clone(), state.links.clone()),
            Err(_) => return BTreeMap::new(),
        };
        let routes = self.filtered_kernel_routes(&config);
        let bird_routes = self.bird_routes_cached();
        sav_apps::generate_sav_table(
            sav_apps::AppContext {
                config: &config,
                routes: &routes,
                bird_routes: &bird_routes,
                links: &links,
            },
            caches.as_deref_mut(),
        )
    }

    fn with_sav_rules_for_app<R>(
        &self,
        active_app: &str,
        consume: impl FnOnce(&BTreeMap<String, SavRule>) -> R,
    ) -> R {
        // Poisoned cache is never reused: the stateless full generator is the fallback.
        let mut caches = if matches!(active_app, "strict_urpf" | "loose_urpf") {
            self.urpf_caches.lock().ok()
        } else {
            None
        };
        let (config, links) = match self.state.lock() {
            Ok(state) => (state.config.clone(), state.links.clone()),
            Err(_) => return consume(&BTreeMap::new()),
        };
        let routes = self.filtered_kernel_routes(&config);
        // uRPF depends on the filtered kernel FIB, not the BIRD RIB.
        let bird_routes = if matches!(active_app, "strict_urpf" | "loose_urpf") {
            Vec::new()
        } else {
            self.bird_routes_cached()
        };
        sav_apps::with_sav_rules(
            &sav_apps::AppContext {
                config: &config,
                routes: &routes,
                bird_routes: &bird_routes,
                links: &links,
            },
            active_app,
            caches.as_deref_mut(),
            consume,
        )
    }

    fn filtered_kernel_routes(&self, config: &ConfigSummary) -> Vec<KernelRoute> {
        let ignore_nets: Vec<Prefix> = if config.use_ignore_nets {
            config
                .ignore_nets
                .iter()
                .filter_map(|prefix| parse_prefix(prefix))
                .collect()
        } else {
            Vec::new()
        };
        self.kernel_routes()
            .into_iter()
            .filter(|route| should_keep_route(route, config.ignore_private, &ignore_nets))
            .collect()
    }

    fn kernel_routes(&self) -> Vec<KernelRoute> {
        let mut routes = Vec::new();
        for (family, args) in [
            (
                4_u8,
                ["-j", "-4", "route", "show", "table", "main"].as_slice(),
            ),
            (
                6_u8,
                ["-j", "-6", "route", "show", "table", "main"].as_slice(),
            ),
        ] {
            let output = match Command::new("ip").args(args).output() {
                Ok(output) => output,
                Err(err) => {
                    self.log(&format!("failed to run ip route for IPv{family}: {err}"));
                    continue;
                }
            };
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                self.log(&format!("ip route failed for IPv{family}: {stderr}"));
                continue;
            }
            let parsed: Value = match serde_json::from_slice(&output.stdout) {
                Ok(parsed) => parsed,
                Err(err) => {
                    self.log(&format!(
                        "failed to parse ip route json for IPv{family}: {err}"
                    ));
                    continue;
                }
            };
            if let Some(items) = parsed.as_array() {
                for item in items {
                    let Some(prefix) = value_string(item, "dst") else {
                        continue;
                    };
                    routes.push(KernelRoute {
                        family,
                        prefix: normalize_prefix_text(&prefix),
                        interface_name: value_string(item, "dev"),
                        gateway: value_string(item, "gateway")
                            .or_else(|| value_string(item, "via")),
                        route_type: value_string(item, "type"),
                        protocol: value_string(item, "protocol"),
                        scope: value_string(item, "scope"),
                    });
                }
            }
        }
        routes
    }

    fn bird_routes_cached(&self) -> Vec<BirdRoute> {
        if let Ok(mut cache) = self.bird_route_cache.lock() {
            if !cache.dirty {
                cache.hit_count += 1;
                return cache.routes.clone();
            }
        }

        match self.fetch_bird_routes_direct() {
            Ok(routes) => {
                if let Ok(mut cache) = self.bird_route_cache.lock() {
                    cache.routes = routes.clone();
                    cache.dirty = false;
                    cache.last_refresh = Some(now_secs());
                    cache.refresh_count += 1;
                    cache.last_error = None;
                }
                routes
            }
            Err(err) => {
                self.log(&format!("BIRD route cache refresh failed: {err}"));
                if let Ok(mut cache) = self.bird_route_cache.lock() {
                    cache.error_count += 1;
                    cache.last_error = Some(err);
                    cache.routes.clone()
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn fetch_bird_routes_direct(&self) -> Result<Vec<BirdRoute>, String> {
        let mut routes = Vec::new();
        let mut client = BirdControlClient::connect(&self.cfg.bird_socket, Duration::from_secs(2))?;
        for table in ["master4", "master6"] {
            let lines = client.command(&format!("show route table {table} all"))?;
            let text = lines.join("\n");
            routes.extend(parse_bird_routes(&text));
        }
        Ok(routes)
    }

    fn run(&self) {
        self.system_check();
        self.log("starting rust thin supervisor");
        let mut last_signal = String::new();
        loop {
            thread::sleep(Duration::from_millis(100));
            let content = fs::read_to_string(&self.cfg.signal_path).unwrap_or_default();
            if content == last_signal {
                continue;
            }
            last_signal = content.clone();
            match Self::parse_signal(&content) {
                Some("start") => self.start(),
                Some("stop") => self.stop(),
                Some(_) | None => {}
            }
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_content_length(header: &str) -> Option<usize> {
    for line in header.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    Some(0)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(value_to_string)
}

fn value_u64(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn value_u8(value: &Value, key: &str) -> Option<u8> {
    value_u64(value, key).and_then(|value| {
        if value <= u8::MAX as u64 {
            Some(value as u8)
        } else {
            None
        }
    })
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(value) => Some(*value),
        Value::String(text) => match text.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        },
        Value::Number(number) => number.as_u64().map(|value| value != 0),
        _ => None,
    }
}

fn config_or_env_bool(root: &Value, keys: &[&str], env_name: &str, default: bool) -> bool {
    if let Ok(value) = env::var(env_name) {
        return parse_bool_text(&value).unwrap_or(default);
    }
    keys.iter()
        .find_map(|key| value_bool(root, key))
        .unwrap_or(default)
}

fn config_or_env_u64(root: &Value, keys: &[&str], env_name: &str, default: u64) -> u64 {
    if let Ok(value) = env::var(env_name) {
        if let Ok(parsed) = value.trim().parse() {
            return parsed;
        }
    }
    keys.iter()
        .find_map(|key| value_u64(root, key))
        .unwrap_or(default)
}

fn parse_bool_text(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn string_vec(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(value_to_string).collect(),
        Some(value) => value_to_string(value).into_iter().collect(),
        None => Vec::new(),
    }
}

fn object_keys(value: Option<&Value>) -> Vec<String> {
    match value.and_then(Value::as_object) {
        Some(map) => map.keys().cloned().collect(),
        None => Vec::new(),
    }
}

fn parse_roa_info(root: &Value) -> BTreeMap<i64, BTreeSet<String>> {
    let mut result = BTreeMap::new();
    for key in ["roa_info", "roa_cache", "roa", "roas"] {
        if let Some(value) = root.get(key) {
            merge_roa_value(value, &mut result);
        }
    }
    result
}

fn merge_roa_value(value: &Value, result: &mut BTreeMap<i64, BTreeSet<String>>) {
    match value {
        Value::Object(map) => {
            if let (Some(asn), Some(prefix)) = (
                map.get("asn")
                    .or_else(|| map.get("origin_asn"))
                    .and_then(asn_from_value),
                map.get("prefix").and_then(value_to_string),
            ) {
                result
                    .entry(asn)
                    .or_default()
                    .insert(normalize_prefix_text(&prefix));
                return;
            }
            for (asn_text, prefixes) in map {
                let Some(asn) = asn_from_text(asn_text) else {
                    continue;
                };
                match prefixes {
                    Value::Array(items) => {
                        for item in items {
                            if let Some(prefix) = item
                                .get("prefix")
                                .and_then(value_to_string)
                                .or_else(|| value_to_string(item))
                            {
                                result
                                    .entry(asn)
                                    .or_default()
                                    .insert(normalize_prefix_text(&prefix));
                            }
                        }
                    }
                    Value::String(prefix) => {
                        result
                            .entry(asn)
                            .or_default()
                            .insert(normalize_prefix_text(prefix));
                    }
                    _ => {}
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                merge_roa_value(item, result);
            }
        }
        _ => {}
    }
}

fn parse_aspa_info(root: &Value) -> BTreeMap<i64, BTreeSet<i64>> {
    let mut result = BTreeMap::new();
    for key in ["aspa_info", "aspa_cache", "aspa", "aspas"] {
        if let Some(value) = root.get(key) {
            merge_aspa_value(value, &mut result);
        }
    }
    result
}

fn merge_aspa_value(value: &Value, result: &mut BTreeMap<i64, BTreeSet<i64>>) {
    match value {
        Value::Object(map) => {
            if let Some(customer) = map
                .get("customer")
                .or_else(|| map.get("customer_asn"))
                .or_else(|| map.get("customer_as"))
                .and_then(asn_from_value)
            {
                merge_aspa_providers(customer, map.get("providers"), result);
                return;
            }
            for (customer_text, providers) in map {
                if let Some(customer) = asn_from_text(customer_text) {
                    merge_aspa_providers(customer, Some(providers), result);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                merge_aspa_value(item, result);
            }
        }
        _ => {}
    }
}

fn merge_aspa_providers(
    customer: i64,
    providers: Option<&Value>,
    result: &mut BTreeMap<i64, BTreeSet<i64>>,
) {
    match providers {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(provider) = asn_from_value(item) {
                    result.entry(customer).or_default().insert(provider);
                }
            }
        }
        Some(value) => {
            if let Some(provider) = asn_from_value(value) {
                result.entry(customer).or_default().insert(provider);
            }
        }
        None => {}
    }
}

fn asn_from_value(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => asn_from_text(text),
        _ => None,
    }
}

fn asn_from_text(text: &str) -> Option<i64> {
    let cleaned = text
        .trim()
        .trim_matches('"')
        .trim_start_matches("AS")
        .trim_start_matches("as")
        .replace("(v4)", "")
        .replace("(v6)", "");
    cleaned.trim().parse().ok()
}

fn interface_name_for(protocol_name: &str, remote_id: Option<&str>) -> String {
    if let Some(remote_id) = remote_id {
        return format!("eth_{remote_id}");
    }
    match protocol_name.rsplit('_').next() {
        Some(peer_id) if !peer_id.is_empty() => format!("eth_{peer_id}"),
        _ => "eth_unknown".to_string(),
    }
}

fn normalize_prefix_text(prefix: &str) -> String {
    if prefix == "default" {
        return prefix.to_string();
    }
    if let Some(parsed) = parse_prefix(prefix) {
        return format!("{}/{}", parsed.addr, parsed.len).to_ascii_lowercase();
    }
    prefix.to_ascii_lowercase()
}

fn parse_prefix(input: &str) -> Option<Prefix> {
    if input == "default" {
        return None;
    }
    let (addr_text, len_text) = match input.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (input, None),
    };
    let addr: IpAddr = addr_text.parse().ok()?;
    let max_len = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let len = len_text
        .and_then(|text| text.parse::<u8>().ok())
        .unwrap_or(max_len)
        .min(max_len);
    Some(Prefix {
        addr: normalize_prefix_addr(addr, len),
        len,
    })
}

fn normalize_prefix_addr(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => {
            let raw = u32::from_be_bytes(addr.octets());
            IpAddr::V4(Ipv4Addr::from((raw & mask_v4(len)).to_be_bytes()))
        }
        IpAddr::V6(addr) => {
            let raw = u128::from_be_bytes(addr.octets());
            IpAddr::V6(Ipv6Addr::from((raw & mask_v6(len)).to_be_bytes()))
        }
    }
}

fn mask_v4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX.checked_shl((32 - len.min(32)) as u32).unwrap_or(0)
    }
}

fn mask_v6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX
            .checked_shl((128 - len.min(128)) as u32)
            .unwrap_or(0)
    }
}

fn prefix_contains(container_prefix: &Prefix, child: &Prefix) -> bool {
    if child.len < container_prefix.len {
        return false;
    }
    match (container_prefix.addr, child.addr) {
        (IpAddr::V4(container), IpAddr::V4(child)) => {
            let mask = mask_v4(container_prefix.len);
            (u32::from_be_bytes(container.octets()) & mask)
                == (u32::from_be_bytes(child.octets()) & mask)
        }
        (IpAddr::V6(container), IpAddr::V6(child)) => {
            let mask = mask_v6(container_prefix.len);
            (u128::from_be_bytes(container.octets()) & mask)
                == (u128::from_be_bytes(child.octets()) & mask)
        }
        _ => false,
    }
}

fn prefix_is_private(prefix: &Prefix) -> bool {
    match prefix.addr {
        IpAddr::V4(addr) => addr.is_private() || addr.is_loopback() || addr.is_link_local(),
        IpAddr::V6(addr) => {
            addr.is_loopback() || addr.is_unique_local() || addr.is_unicast_link_local()
        }
    }
}

fn prefix_is_never_sav_source(prefix: &Prefix) -> bool {
    match prefix.addr {
        IpAddr::V4(addr) => addr.is_loopback() || addr.is_link_local(),
        IpAddr::V6(addr) => addr.is_loopback() || addr.is_unicast_link_local(),
    }
}

fn should_keep_route(route: &KernelRoute, ignore_private: bool, ignore_nets: &[Prefix]) -> bool {
    if route.prefix == "default" || route.interface_name.as_deref() == Some("lo") {
        return false;
    }
    let route_type = route
        .route_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        route_type.as_str(),
        "blackhole" | "unreachable" | "prohibit" | "throw"
    ) {
        return false;
    }
    let Some(prefix) = parse_prefix(&route.prefix) else {
        return false;
    };
    if prefix.len == 0 {
        return false;
    }
    if prefix_is_never_sav_source(&prefix) {
        return false;
    }
    if ignore_private && prefix_is_private(&prefix) {
        return false;
    }
    !ignore_nets
        .iter()
        .any(|ignore_prefix| prefix_contains(ignore_prefix, &prefix))
}

#[derive(Clone, Debug)]
struct PartialBirdRoute {
    prefix: String,
    interface_name: Option<String>,
    as_path: Vec<u64>,
    selected: bool,
}

fn parse_bird_routes(text: &str) -> Vec<BirdRoute> {
    let mut routes = Vec::new();
    let mut current_prefix: Option<String> = None;
    let mut current_route: Option<PartialBirdRoute> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("BIRD ") || trimmed.starts_with("Table ") {
            continue;
        }

        let starts_new_prefix = !line.starts_with(char::is_whitespace)
            && trimmed
                .split_whitespace()
                .next()
                .map(|token| token.contains('/'))
                .unwrap_or(false);
        if starts_new_prefix {
            finish_bird_route(&mut routes, current_route.take());
            if let Some(prefix) = trimmed.split_whitespace().next() {
                current_prefix = Some(normalize_prefix_text(prefix));
            }
            if trimmed.contains("unicast [") {
                if let Some(prefix) = current_prefix.clone() {
                    current_route = Some(PartialBirdRoute {
                        prefix,
                        interface_name: None,
                        as_path: Vec::new(),
                        selected: trimmed.contains("] *"),
                    });
                }
            }
            continue;
        }

        if trimmed.starts_with("unicast [") {
            finish_bird_route(&mut routes, current_route.take());
            if let Some(prefix) = current_prefix.clone() {
                current_route = Some(PartialBirdRoute {
                    prefix,
                    interface_name: None,
                    as_path: Vec::new(),
                    selected: trimmed.contains("] *"),
                });
            }
            continue;
        }

        if let Some(route) = current_route.as_mut() {
            if let Some(interface_name) = parse_bird_via_interface(trimmed) {
                route.interface_name = Some(interface_name);
            } else if let Some(as_path) = trimmed.strip_prefix("BGP.as_path:") {
                route.as_path = parse_as_path(as_path);
            }
        }
    }
    finish_bird_route(&mut routes, current_route);
    routes
}

fn finish_bird_route(routes: &mut Vec<BirdRoute>, route: Option<PartialBirdRoute>) {
    let Some(route) = route else {
        return;
    };
    let origin_as = route.as_path.last().cloned();
    if route.interface_name.is_none() && route.as_path.is_empty() {
        return;
    }
    routes.push(BirdRoute {
        prefix: route.prefix,
        interface_name: route.interface_name,
        as_path: route.as_path,
        origin_as,
        selected: route.selected,
    });
}

fn parse_bird_via_interface(line: &str) -> Option<String> {
    let (_, interface) = line.rsplit_once(" on ")?;
    interface
        .split_whitespace()
        .next()
        .map(|value| value.trim_matches(',').to_string())
        .filter(|value| !value.is_empty())
}

fn parse_as_path(text: &str) -> Vec<u64> {
    text.split_whitespace()
        .filter_map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_digit())
                .parse::<u64>()
                .ok()
        })
        .collect()
}

fn find_string_for_keys(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key).and_then(value_to_string) {
                    return Some(found);
                }
            }
            for child in map.values() {
                if let Some(found) = find_string_for_keys(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => {
            for child in items {
                if let Some(found) = find_string_for_keys(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn find_bool_for_keys(value: &Value, keys: &[&str]) -> Option<bool> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key) {
                    match found {
                        Value::Bool(value) => return Some(*value),
                        Value::String(value) => match value.to_ascii_lowercase().as_str() {
                            "true" | "up" | "established" | "running" | "start" | "started" => {
                                return Some(true)
                            }
                            "false" | "down" | "idle" | "stop" | "stopped" | "disabled" => {
                                return Some(false)
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
            for child in map.values() {
                if let Some(found) = find_bool_for_keys(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => {
            for child in items {
                if let Some(found) = find_bool_for_keys(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn extract_protocol_name(payload: &Value, msg_type: &str) -> Option<String> {
    let preferred = if msg_type == "link_state_change" {
        [
            "/msg/protocol_name",
            "/protocol_name",
            "/msg/msg/protocol_name",
        ]
    } else {
        [
            "/msg/msg/protocol_name",
            "/msg/protocol_name",
            "/protocol_name",
        ]
    };
    for pointer in preferred {
        if let Some(found) = payload.pointer(pointer).and_then(value_to_string) {
            return Some(found);
        }
    }
    find_string_for_keys(payload, &["protocol_name"])
}

fn extract_link_type(payload: &Value, msg_type: &str) -> Option<String> {
    if msg_type == "link_state_change" {
        return None;
    }
    let channels = payload
        .pointer("/msg/msg/channels")
        .or_else(|| payload.pointer("/msg/channels"))
        .or_else(|| payload.get("channels"));
    if contains_channel(channels, "rpdp") {
        Some("rpdp_bgp".to_string())
    } else {
        Some("bgp".to_string())
    }
}

fn contains_channel(value: Option<&Value>, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    match value {
        Some(Value::Array(items)) => items.iter().any(|item| {
            value_to_string(item)
                .map(|item| item.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        }),
        Some(value) => value_to_string(value)
            .map(|item| item.to_ascii_lowercase().contains(&needle))
            .unwrap_or(false),
        None => false,
    }
}

fn extract_status(payload: &Value) -> Option<bool> {
    if let Some(found) = find_bool_for_keys(payload, &["status", "up", "is_up", "enabled"]) {
        return Some(found);
    }
    let text = find_string_for_keys(
        payload,
        &[
            "new_state",
            "state",
            "link_state",
            "proto_state",
            "protocol_state",
        ],
    )?;
    let text = text.to_ascii_lowercase();
    if text.contains("down")
        || text.contains("stop")
        || text.contains("disable")
        || text.contains("idle")
    {
        Some(false)
    } else if text.contains("up")
        || text.contains("start")
        || text.contains("establish")
        || text.contains("run")
    {
        Some(true)
    } else {
        None
    }
}

fn write_response(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn main() {
    match Agent::new() {
        Ok(agent) => agent.run(),
        Err(err) => {
            eprintln!("failed to start sav_agent: {err}");
            std::process::exit(1);
        }
    }
}
