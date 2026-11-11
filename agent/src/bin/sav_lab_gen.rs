use sav_agent::paths::SavopLayout;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[path = "sav_lab_gen/output.rs"]
mod output;
#[path = "sav_lab_gen/policy.rs"]
mod policy;

const LINK_TYPE: &str = "dsav";
const CLAB_IMAGE: &str = "savop_runtime_clab";
const DEFAULT_CLAB_MGMT_IPV4_SUBNET: &str = "172.30.0.0/16";

#[derive(Clone)]
struct Args {
    layout: SavopLayout,
    config: PathBuf,
    out: PathBuf,
    agent_mode: String,
    ip_version: Option<u8>,
    bird_debug: bool,
}

#[derive(Clone)]
struct LinkInfo {
    peer_id: String,
    local_ip: String,
    remote_ip: String,
    remote_as: u64,
    local_role: &'static str,
    remote_role: &'static str,
    explicit_policy: bool,
}

#[derive(Clone)]
struct PhysicalLink {
    index: usize,
    src: String,
    dst: String,
    src_ip: String,
    dst_ip: String,
    prefix_len: u8,
}

fn usage() -> ! {
    eprintln!(
        "usage: sav_lab_gen [--config PATH] [--out PATH] [--agent-mode rust] [--ip-version auto|4|6] [--bird-debug]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let layout = load_layout_or_exit();
    let mut args = env::args().skip(1);
    let mut config = layout.config_dir.join("5_nodes_v6.json");
    let mut out = layout.run_dir.clone();
    let mut agent_mode = "rust".to_string();
    let mut ip_version = None;
    let mut bird_debug = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config = layout.resolve_config_arg(&args.next().unwrap_or_else(usage_string))
            }
            "--out" => {
                out = layout.resolve_root_arg(&args.next().unwrap_or_else(usage_string));
            }
            "--agent-mode" => agent_mode = args.next().unwrap_or_else(usage_string),
            "--ip-version" => {
                let value = args.next().unwrap_or_else(usage_string);
                ip_version = match value.as_str() {
                    "auto" => None,
                    "4" => Some(4),
                    "6" => Some(6),
                    _ => usage(),
                };
            }
            "--bird-debug" => bird_debug = true,
            _ => usage(),
        }
    }

    if agent_mode != "rust" {
        eprintln!("sav_lab_gen is Rust-only for now; use --agent-mode rust");
        std::process::exit(2);
    }

    Args {
        layout,
        config,
        out,
        agent_mode,
        ip_version,
        bird_debug,
    }
}

fn usage_string() -> String {
    usage();
}

fn load_layout_or_exit() -> SavopLayout {
    SavopLayout::load().unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    })
}

fn main() -> io::Result<()> {
    generate(parse_args())
}

fn generate(mut args: Args) -> io::Result<()> {
    // Read-only preflight: no output directory is created until inputs pass.
    args.out = output::validate_destination(&args.layout, &args.out)?;
    let base: Value = serde_json::from_str(&fs::read_to_string(&args.config)?)?;
    let devices = base
        .get("devices")
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing devices"))?;
    let links = base
        .get("links")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing links"))?;
    validate_devices(devices)?;
    let policies = policy::parse(&base, devices, links)?;
    let ip_version = args.ip_version.unwrap_or_else(|| infer_ip_version(&base));
    let prefix_len = link_prefix_len(ip_version);
    let mut node_ids: Vec<String> = devices.keys().cloned().collect();
    node_ids.sort_by_key(|id| id.parse::<u64>().unwrap_or(u64::MAX));
    let router_ids: BTreeMap<String, String> = node_ids
        .iter()
        .map(|id| (id.clone(), router_id(id)))
        .collect();

    let mut link_state: BTreeMap<String, Vec<LinkInfo>> =
        node_ids.iter().map(|id| (id.clone(), Vec::new())).collect();
    let mut physical_links = Vec::new();

    for (idx, raw_link) in links.iter().enumerate() {
        let arr = raw_link
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "link must be array"))?;
        let src = value_string(arr.first()).ok_or_else(|| io_err("bad link src"))?;
        let dst = value_string(arr.get(1)).ok_or_else(|| io_err("bad link dst"))?;
        let link_type = value_string(arr.get(2)).unwrap_or_default();
        if link_type != LINK_TYPE {
            return Err(io_err(&format!("unsupported link type: {link_type}")));
        }
        let index = idx + 1;
        let (src_ip, dst_ip) = link_ips(index, ip_version);
        let src_as = device_as(devices, &src)?;
        let dst_as = device_as(devices, &dst)?;
        let (src_role, dst_role, explicit_policy) = if src_as == dst_as {
            ("internal", "internal", false)
        } else if let Some(roles) = policies
            .as_ref()
            .and_then(|p| p.get(&(src.clone(), dst.clone())).copied())
        {
            (roles.0, roles.1, true)
        } else if policies.is_some() {
            return Err(io_err("missing policy for inter-AS physical link"));
        } else {
            ("peer", "peer", false)
        };
        physical_links.push(PhysicalLink {
            index,
            src: src.clone(),
            dst: dst.clone(),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            prefix_len,
        });
        link_state.get_mut(&src).unwrap().push(LinkInfo {
            peer_id: dst.clone(),
            local_ip: src_ip.clone(),
            remote_ip: dst_ip.clone(),
            remote_as: dst_as,
            local_role: src_role,
            remote_role: dst_role,
            explicit_policy,
        });
        link_state.get_mut(&dst).unwrap().push(LinkInfo {
            peer_id: src.clone(),
            local_ip: dst_ip,
            remote_ip: src_ip,
            remote_as: src_as,
            local_role: dst_role,
            remote_role: src_role,
            explicit_policy,
        });
    }

    // Missing router artifacts must not leave an output directory behind.
    for name in ["bird", "birdc", "birdcl"] {
        let source = args.layout.router_dir.join(name);
        if !fs::metadata(&source)?.is_file() {
            return Err(io_err(&format!(
                "not a router binary: {}",
                source.display()
            )));
        }
        fs::File::open(source)?;
    }
    output::create_destination(&args.layout, &args.out)?;

    let artifact_context = NodeArtifactContext {
        base_dir: &args.out,
        router_ids: &router_ids,
        base: &base,
        ip_version,
        bird_debug: args.bird_debug,
    };
    for node_id in &node_ids {
        write_node_artifacts(
            &artifact_context,
            node_id,
            devices.get(node_id).unwrap(),
            link_state.get(node_id).unwrap(),
        )?;
    }
    copy_bird_tools(&args.layout, &args.out)?;
    fs::write(
        args.out.join("active_signal.json"),
        signal_text("stop", &node_ids),
    )?;
    write_containerlab_artifacts(
        &args.layout,
        &args.out,
        &node_ids,
        &physical_links,
        &args.agent_mode,
        args.bird_debug,
    )?;
    output::write_manifest(&args.out, &args.config)?;
    println!(
        "generated {} nodes under {}",
        node_ids.len(),
        args.out.display()
    );
    println!("config: {}", args.config.display());
    println!("ip version: IPv{ip_version}");
    println!(
        "containerlab: {}",
        args.out.join("topology.clab.yml").display()
    );
    println!("agent mode: {}", args.agent_mode);
    println!(
        "bird debug: {}",
        if args.bird_debug { "all" } else { "states" }
    );
    Ok(())
}

fn validate_devices(devices: &Map<String, Value>) -> io::Result<()> {
    if devices.is_empty() {
        return Err(io_err("devices must not be empty"));
    }
    for (id, node) in devices {
        // IDs become directory names and shell arguments: reject path traversal
        // and ambiguous/non-numeric identifiers before any filesystem writes.
        if !matches!(id.parse::<u64>(), Ok(n) if n > 0 && n.to_string() == *id) {
            return Err(io_err(&format!("node ID must be a positive integer: {id}")));
        }
        let asn = device_as(devices, id)?;
        if asn == 0 || asn > u32::MAX as u64 {
            return Err(io_err(&format!("invalid AS number for node {id}")));
        }
        let prefixes: Vec<&str> = match node.get("prefixes") {
            None => Vec::new(),
            Some(Value::Object(items)) => items.keys().map(String::as_str).collect(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .ok_or_else(|| io_err("prefix must be a string"))
                })
                .collect::<io::Result<_>>()?,
            _ => return Err(io_err("prefixes must be an object or an array")),
        };
        for prefix in prefixes {
            let valid = prefix.split_once('/').is_some_and(|(addr, len)| {
                match (addr.parse::<std::net::IpAddr>(), len.parse::<u8>()) {
                    (Ok(std::net::IpAddr::V4(_)), Ok(n)) => n <= 32,
                    (Ok(std::net::IpAddr::V6(_)), Ok(n)) => n <= 128,
                    _ => false,
                }
            });
            if !valid {
                return Err(io_err(&format!("invalid prefix for node {id}: {prefix}")));
            }
        }
    }
    Ok(())
}

fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn value_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn device_as(devices: &Map<String, Value>, node_id: &str) -> io::Result<u64> {
    devices
        .get(node_id)
        .and_then(|node| node.get("as"))
        .and_then(Value::as_u64)
        .ok_or_else(|| io_err(&format!("missing AS for node {node_id}")))
}

fn router_id(node_id: &str) -> String {
    let id = node_id.parse::<u64>().unwrap_or(0);
    let third = (id / 256) % 256;
    let fourth = id % 256;
    format!("172.31.{third}.{fourth}")
}

fn infer_ip_version(base: &Value) -> u8 {
    if let Some(version) = base.get("auto_ip_version").and_then(Value::as_u64) {
        if version == 4 || version == 6 {
            return version as u8;
        }
    }
    if let Some(devices) = base.get("devices").and_then(Value::as_object) {
        for node in devices.values() {
            let prefixes = prefix_items(node);
            if let Some(prefix) = prefixes.keys().next() {
                return if prefix.contains(':') { 6 } else { 4 };
            }
        }
    }
    6
}

fn link_prefix_len(ip_version: u8) -> u8 {
    if ip_version == 6 {
        124
    } else {
        30
    }
}

fn link_ips(index: usize, ip_version: u8) -> (String, String) {
    if ip_version == 6 {
        (format!("fec::{index}:1"), format!("fec::{index}:2"))
    } else {
        let subnet = (index as u32).saturating_mul(4);
        let second = (subnet >> 16) & 0xff;
        let third = (subnet >> 8) & 0xff;
        let fourth = subnet & 0xfc;
        (
            format!("10.{second}.{third}.{}", fourth + 1),
            format!("10.{second}.{third}.{}", fourth + 2),
        )
    }
}

fn prefix_items(node: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    match node.get("prefixes") {
        Some(Value::Object(map)) => {
            for (prefix, meta) in map {
                out.insert(norm_prefix(prefix), meta.clone());
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(prefix) = item.as_str() {
                    out.insert(norm_prefix(prefix), json!({}));
                }
            }
        }
        _ => {}
    }
    out
}

fn norm_prefix(prefix: &str) -> String {
    let Some((addr, plen_text)) = prefix.split_once('/') else {
        return if prefix.contains(':') {
            prefix.to_ascii_lowercase()
        } else {
            prefix.to_string()
        };
    };
    if prefix.contains(':') {
        let plen: u8 = plen_text.parse::<u8>().unwrap_or(128).min(128);
        if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
            let raw = u128::from_be_bytes(ip.octets());
            let mask = if plen == 0 {
                0
            } else {
                u128::MAX.checked_shl((128 - plen) as u32).unwrap_or(0)
            };
            let network = std::net::Ipv6Addr::from((raw & mask).to_be_bytes());
            return format!("{network}/{plen}").to_ascii_lowercase();
        }
        return format!("{addr}/{plen}").to_ascii_lowercase();
    }
    let plen: u8 = plen_text.parse::<u8>().unwrap_or(32).min(32);
    let mut octets = [0_u8; 4];
    for (idx, part) in addr.split('.').take(4).enumerate() {
        octets[idx] = part.parse().unwrap_or(0);
    }
    let raw = u32::from_be_bytes(octets);
    let mask = if plen == 0 {
        0
    } else {
        u32::MAX.checked_shl((32 - plen) as u32).unwrap_or(0)
    };
    let network = (raw & mask).to_be_bytes();
    format!(
        "{}.{}.{}.{}/{}",
        network[0], network[1], network[2], network[3], plen
    )
}

fn bird_static_block(name: &str, family: &str, routes: &[String]) -> String {
    let mut lines = vec![
        format!("protocol static {name} {{"),
        format!("  {family} {{ export all; import all; }};"),
    ];
    for route in routes {
        lines.push(format!("  route {route} blackhole;"));
    }
    lines.push("};".to_string());
    lines.join("\n")
}

fn bird_config(
    node_id: &str,
    node: &Value,
    links: &[LinkInfo],
    ip_version: u8,
    bird_debug: bool,
) -> String {
    let prefixes = prefix_items(node);
    let v4_routes: Vec<String> = prefixes
        .keys()
        .filter(|prefix| !prefix.contains(':'))
        .cloned()
        .collect();
    let v6_routes: Vec<String> = prefixes
        .keys()
        .filter(|prefix| prefix.contains(':'))
        .cloned()
        .collect();
    let family = if ip_version == 6 { "ipv6" } else { "ipv4" };
    let rpdp_family = if ip_version == 6 { "rpdp6" } else { "rpdp4" };
    let local_as = node.get("as").and_then(Value::as_u64).unwrap_or(0);
    let debug = if bird_debug {
        "  debug all;"
    } else {
        "  debug { states };"
    };

    let mut lines = vec![
        "log stderr all;".to_string(),
        format!("router id {};", router_id(node_id)),
        "ipv4 table master4 { sorted 1; };".to_string(),
        "ipv6 table master6 { sorted 1; };".to_string(),
        String::new(),
        "protocol device {".to_string(),
        "  scan time 1;".to_string(),
        "  interface \"eth_*\", \"savop_dummy\";".to_string(),
        "};".to_string(),
        String::new(),
        "protocol kernel krt4 {".to_string(),
        "  scan time 1;".to_string(),
        "  ipv4 { export all; import none; };".to_string(),
        "  learn;".to_string(),
        "  persist;".to_string(),
        "};".to_string(),
        String::new(),
        "protocol kernel krt6 {".to_string(),
        "  scan time 1;".to_string(),
        "  ipv6 { export all; import none; };".to_string(),
        "  learn;".to_string(),
        "  persist;".to_string(),
        "};".to_string(),
        String::new(),
        "protocol direct {".to_string(),
        "  ipv4;".to_string(),
        "  ipv6;".to_string(),
        "  interface \"eth_*\", \"savop_dummy\";".to_string(),
        "};".to_string(),
        String::new(),
        bird_static_block("static4", "ipv4", &v4_routes),
        String::new(),
        bird_static_block("static6", "ipv6", &v6_routes),
        String::new(),
        "template bgp dsav_tpl {".to_string(),
        format!("  local as {local_as};"),
        "  long lived graceful restart on;".to_string(),
        debug.to_string(),
        "  enable extended messages;".to_string(),
        format!("  {family} {{"),
        "    import all;".to_string(),
        "    export all;".to_string(),
        "    next hop self on;".to_string(),
        "  };".to_string(),
        format!("  {rpdp_family} {{"),
        "    import none;".to_string(),
        "    export none;".to_string(),
        "  };".to_string(),
        "};".to_string(),
        String::new(),
    ];

    for link in links {
        let proto = format!("{LINK_TYPE}_{node_id}_{}", link.peer_id);
        lines.push(format!("protocol bgp {proto} from dsav_tpl {{"));
        lines.push(format!(
            "  description \"SAVOP dsav link r{node_id}-r{}\";",
            link.peer_id
        ));
        if local_as == link.remote_as {
            lines.push("  rr client;".to_string());
        }
        lines.push(format!("  source address {};", link.local_ip));
        lines.push(format!(
            "  neighbor {} as {};",
            link.remote_ip, link.remote_as
        ));
        lines.push(format!("  interface \"eth_{}\";", link.peer_id));
        lines.push("  direct;".to_string());
        lines.push("  connect delay time 1;".to_string());
        if link.explicit_policy {
            let customer_protocols: Vec<String> = links
                .iter()
                .filter(|x| x.remote_role == "customer")
                .map(|x| format!("{LINK_TYPE}_{node_id}_{}", x.peer_id))
                .collect();
            lines.extend(policy::channel(
                family,
                link.remote_role,
                &customer_protocols,
            ));
        }
        lines.push("};".to_string());
        lines.push(String::new());
    }
    lines.join("\n")
}

fn sa_config(
    node_id: &str,
    node: &Value,
    links: &[LinkInfo],
    router_ids: &BTreeMap<String, String>,
    base: &Value,
    ip_version: u8,
) -> Value {
    let mut link_map = Map::new();
    for link in links {
        link_map.insert(
            format!("{LINK_TYPE}_{node_id}_{}", link.peer_id),
            json!({
                "link_type": LINK_TYPE,
                "remote_ip": link.remote_ip,
                "remote_id": link.peer_id,
                "remote_as": link.remote_as,
                "local_ip": link.local_ip,
                "local_role": link.local_role,
                "remote_role": link.remote_role,
                "remote_location": "core",
            }),
        );
    }
    let apps = configured_apps(base);
    let enabled = base
        .get("active_sav_app")
        .and_then(Value::as_str)
        .unwrap_or("rpdp");
    let prefixes = Value::Object(prefix_items(node).into_iter().collect());
    let mut as_scope = Map::new();
    for (id, rid) in router_ids {
        as_scope.insert(id.clone(), json!({"router_id": rid, "ips": []}));
    }
    let ignore_nets = if ip_version == 6 {
        json!(["fec::/16"])
    } else {
        json!(["10.0.0.0/8"])
    };
    json!({
        "apps": apps,
        "enabled_sav_app": enabled,
        "fib_stable_threshold": 5,
        "ca_host": null,
        "ca_port": null,
        "grpc_config": {"server_addr": "0.0.0.0:5000", "server_enabled": true},
        "quic_config": {"server_enabled": true},
        "auto_ip_version": ip_version,
        "ignore_nets": base.get("ignore_nets").cloned().unwrap_or(ignore_nets),
        "use_ignore_nets": true,
        "local_as": node.get("as").and_then(Value::as_u64).unwrap_or(0),
        "device_id": node_id,
        "prefixes": prefixes,
        "router_id": router_id(node_id),
        "as_scope": as_scope,
        "enable_rpki": base.get("enable_rpki").and_then(Value::as_bool).unwrap_or(false),
        "ignore_private": false,
        "prefix_method": base.get("prefix_method").and_then(Value::as_str).unwrap_or("blackhole"),
        "location": "core",
        "link_map": link_map,
    })
}

fn default_apps() -> Value {
    json!([
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
        "passport"
    ])
}

fn configured_apps(base: &Value) -> Value {
    for key in ["sav_apps", "apps"] {
        if let Some(Value::Array(items)) = base.get(key) {
            if !items.is_empty() {
                return Value::Array(items.clone());
            }
        }
    }
    default_apps()
}

struct NodeArtifactContext<'a> {
    base_dir: &'a Path,
    router_ids: &'a BTreeMap<String, String>,
    base: &'a Value,
    ip_version: u8,
    bird_debug: bool,
}

fn write_node_artifacts(
    ctx: &NodeArtifactContext<'_>,
    node_id: &str,
    node: &Value,
    links: &[LinkInfo],
) -> io::Result<()> {
    let node_dir = ctx.base_dir.join(node_id);
    fs::create_dir_all(node_dir.join("log"))?;
    fs::write(
        node_dir.join("bird.conf"),
        bird_config(node_id, node, links, ctx.ip_version, ctx.bird_debug),
    )?;
    fs::write(
        node_dir.join("sa.json"),
        serde_json::to_string_pretty(&sa_config(
            node_id,
            node,
            links,
            ctx.router_ids,
            ctx.base,
            ctx.ip_version,
        ))? + "
",
    )?;
    Ok(())
}
fn copy_bird_tools(layout: &SavopLayout, base_dir: &Path) -> io::Result<()> {
    for name in ["bird", "birdc", "birdcl"] {
        let dst = base_dir.join(name);
        fs::copy(layout.router_dir.join(name), &dst)?;
        fs::set_permissions(dst, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn signal_text(command: &str, node_ids: &[String]) -> String {
    serde_json::to_string_pretty(&json!({"command": command, "command_scope": node_ids})).unwrap()
        + "\n"
}

fn q(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn link_mac(index: usize, node_id: &str, peer_id: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in format!("{index}:{node_id}:{peer_id}").as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let bytes = hash.to_be_bytes();
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]
    )
}

fn iface_for(peer_id: &str) -> String {
    format!("eth_{peer_id}")
}

fn write_script(path: &Path, lines: Vec<String>) -> io::Result<()> {
    fs::write(path, lines.join("\n") + "\n")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn short_hash(value: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", hash as u32)
}

fn clab_lab_name(out: &Path) -> String {
    let raw = out
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lab");
    let mut base = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while base.contains("--") {
        base = base.replace("--", "-");
    }
    base = base.trim_matches('-').to_string();
    if base.is_empty() {
        base = "lab".to_string();
    }
    if base.len() > 36 {
        base.truncate(36);
        base = base.trim_matches('-').to_string();
    }
    format!("savop-{base}-{}", short_hash(&out.display().to_string()))
}

fn prepare_libs_script(image: &str) -> Vec<String> {
    vec![
        "#!/usr/bin/env bash".to_string(),
        "set -euo pipefail".to_string(),
        "cd \"$(dirname \"$0\")\"".to_string(),
        "mkdir -p lib".to_string(),
        "if [ ! -e lib/libssh-gcrypt.so.4 ]; then".to_string(),
        format!("  docker run --rm -v \"$PWD/lib:/out\" {} sh -lc '", q(image)),
        "    cp -L /lib/x86_64-linux-gnu/libssh-gcrypt.so.4 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libgcrypt.so.20 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libgpg-error.so.0 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libz.so.1 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libgssapi_krb5.so.2 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libkrb5.so.3 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libk5crypto.so.3 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/lib_com_err.so.2 /out/ 2>/dev/null || cp -L /lib/x86_64-linux-gnu/libcom_err.so.2 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libkrb5support.so.0 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libkeyutils.so.1 /out/;".to_string(),
        "    cp -L /lib/x86_64-linux-gnu/libresolv.so.2 /out/;".to_string(),
        "  '".to_string(),
        "fi".to_string(),
    ]
}

fn write_containerlab_artifacts(
    layout: &SavopLayout,
    out: &Path,
    node_ids: &[String],
    physical_links: &[PhysicalLink],
    agent_mode: &str,
    bird_debug: bool,
) -> io::Result<()> {
    let lab_name = clab_lab_name(out);
    let node_list = node_ids.join(" ");
    let container_prefix = format!("clab-{lab_name}-r");
    let agent_bin = layout.resolve_binary("sav_agent");
    let mgmt_ipv4_subnet = env::var("SAVOP_CLAB_MGMT_IPV4_SUBNET")
        .unwrap_or_else(|_| DEFAULT_CLAB_MGMT_IPV4_SUBNET.to_string());

    fs::write(
        out.join("devices.yml"),
        format!("# generated by sav_lab_gen\n# nodes: {}\n", node_ids.len()),
    )?;
    fs::write(out.join(".clab_name"), format!("{lab_name}\n"))?;

    let batch_dir = out.join("clab_batches");
    let start_dir = out.join("clab_start");
    fs::create_dir(&batch_dir)?;
    fs::create_dir(&start_dir)?;

    let mut node_batches: BTreeMap<String, Vec<String>> = node_ids
        .iter()
        .map(|node_id| {
            (
                node_id.clone(),
                vec!["set -eu".to_string(), "ip link set lo up".to_string()],
            )
        })
        .collect();

    let mut topology = vec![
        "# generated by sav_lab_gen".to_string(),
        format!("name: {lab_name}"),
        "mgmt:".to_string(),
        format!("  network: {lab_name}-mgmt"),
        format!("  ipv4-subnet: {mgmt_ipv4_subnet}"),
        "topology:".to_string(),
        "  kinds:".to_string(),
        "    linux:".to_string(),
        format!("      image: {CLAB_IMAGE}"),
        "      cmd: sleep infinity".to_string(),
        "      binds:".to_string(),
        format!("        - {}:/savop/lab", out.display()),
        format!(
            "        - {}:/usr/local/bin/sav_agent:ro",
            agent_bin.display()
        ),
        "  nodes:".to_string(),
    ];
    for node_id in node_ids {
        topology.push(format!("    r{node_id}:"));
        topology.push("      kind: linux".to_string());
    }
    topology.push("  links:".to_string());
    for link in physical_links {
        topology.push(format!(
            "    - endpoints: [\"r{}:{}\", \"r{}:{}\"]",
            link.src,
            iface_for(&link.dst),
            link.dst,
            iface_for(&link.src)
        ));

        let src_mac = link_mac(link.index, &link.src, &link.dst);
        let dst_mac = link_mac(link.index, &link.dst, &link.src);
        let src_iface = iface_for(&link.dst);
        let dst_iface = iface_for(&link.src);
        node_batches.get_mut(&link.src).unwrap().extend([
            format!("ip link set {src_iface} address {src_mac}"),
            format!("ip link set {src_iface} txqueuelen 10000"),
            format!(
                "ip addr add {}/{} dev {src_iface}",
                link.src_ip, link.prefix_len
            ),
            format!(
                "ip neigh replace {} lladdr {dst_mac} nud permanent dev {src_iface}",
                link.dst_ip
            ),
            format!("ip link set {src_iface} up"),
        ]);
        node_batches.get_mut(&link.dst).unwrap().extend([
            format!("ip link set {dst_iface} address {dst_mac}"),
            format!("ip link set {dst_iface} txqueuelen 10000"),
            format!(
                "ip addr add {}/{} dev {dst_iface}",
                link.dst_ip, link.prefix_len
            ),
            format!(
                "ip neigh replace {} lladdr {src_mac} nud permanent dev {dst_iface}",
                link.src_ip
            ),
            format!("ip link set {dst_iface} up"),
        ]);
    }
    fs::write(out.join("topology.clab.yml"), topology.join("\n") + "\n")?;

    for (node_id, lines) in node_batches {
        fs::write(
            batch_dir.join(format!("{node_id}.sh")),
            lines.join("\n") + "\n",
        )?;
    }
    for node_id in node_ids {
        fs::write(
            start_dir.join(format!("{node_id}.sh")),
            [
                "#!/bin/sh",
                "set -eu",
                &format!("mkdir -p /savop/lab/{node_id}/log"),
                &format!(
                    "if [ -f /savop/lab/{node_id}/supervisor.pid ] && kill -0 \"$(cat /savop/lab/{node_id}/supervisor.pid)\" 2>/dev/null; then exit 0; fi"
                ),
                &format!(
                    "nohup env LD_LIBRARY_PATH=/savop/lab/lib PATH=/savop/lab:$PATH SAVOP_DATA_PATH=/savop/lab/{node_id} SAVOP_SIGNAL_PATH=/savop/lab/active_signal.json SAVOP_CONFIG_PATH=/savop/lab/{node_id}/sa.json SAVOP_LOG_DIR=/savop/lab/{node_id}/log SAVOP_BIRD_BIN=/savop/lab/bird SAVOP_BIRD_CONFIG=/savop/lab/{node_id}/bird.conf SAVOP_BIRD_SOCKET=/savop/lab/{node_id}/bird.ctl SAVOP_BIRD_PID_FILE=/savop/lab/{node_id}/bird.pid /usr/local/bin/sav_agent > /savop/lab/{node_id}/log/supervisor.out 2>&1 &"
                ),
                &format!("echo $! > /savop/lab/{node_id}/supervisor.pid"),
            ]
            .join("\n")
                + "\n",
        )?;
    }

    let start_signal = signal_text("start", node_ids);
    let stop_signal = signal_text("stop", node_ids);
    write_script(
        &out.join("setup_clab.sh"),
        vec![
            "#!/usr/bin/env bash".to_string(),
            "set -euo pipefail".to_string(),
            "cd \"$(dirname \"$0\")\"".to_string(),
            "./destroy_clab.sh >/dev/null 2>&1 || true".to_string(),
            "./prepare_libs.sh".to_string(),
            "containerlab deploy -t topology.clab.yml".to_string(),
            "CLAB_SETUP_JOBS=\"${CLAB_SETUP_JOBS:-$(nproc 2>/dev/null || echo 8)}\"".to_string(),
            "if [ \"$CLAB_SETUP_JOBS\" -gt 32 ]; then CLAB_SETUP_JOBS=32; fi".to_string(),
            "if [ \"$CLAB_SETUP_JOBS\" -lt 1 ]; then CLAB_SETUP_JOBS=1; fi".to_string(),
            "wait_for_slot() {".to_string(),
            "  while [ \"$(jobs -rp | wc -l)\" -ge \"$CLAB_SETUP_JOBS\" ]; do".to_string(),
            "    wait -n".to_string(),
            "  done".to_string(),
            "}".to_string(),
            "wait_all() {".to_string(),
            "  local pid".to_string(),
            "  for pid in $(jobs -rp); do wait \"$pid\"; done".to_string(),
            "}".to_string(),
            format!("CONTAINER_PREFIX={}", q(&container_prefix)),
            format!("for n in {node_list}; do"),
            "  docker exec -i \"${CONTAINER_PREFIX}${n}\" sh < \"clab_batches/${n}.sh\" &"
                .to_string(),
            "  wait_for_slot".to_string(),
            "done".to_string(),
            "wait_all".to_string(),
        ],
    )?;
    write_script(
        &out.join("start_clab.sh"),
        vec![
            "#!/usr/bin/env bash".to_string(),
            "set -euo pipefail".to_string(),
            "cd \"$(dirname \"$0\")\"".to_string(),
            "cat > active_signal.json <<'JSON'".to_string(),
            start_signal.trim_end().to_string(),
            "JSON".to_string(),
            "START_BATCH_SIZE=\"${START_BATCH_SIZE:-0}\"".to_string(),
            "START_BATCH_DELAY_SEC=\"${START_BATCH_DELAY_SEC:-0}\"".to_string(),
            "START_BATCH_LAUNCHED=0".to_string(),
            format!("START_BATCH_TOTAL={}", node_ids.len()),
            format!("CONTAINER_PREFIX={}", q(&container_prefix)),
            format!("for n in {node_list}; do"),
            "  docker exec -i \"${CONTAINER_PREFIX}${n}\" sh < \"clab_start/${n}.sh\"".to_string(),
            "  START_BATCH_LAUNCHED=$((START_BATCH_LAUNCHED + 1))".to_string(),
            "  if [ \"$START_BATCH_SIZE\" -gt 0 ] && [ \"$START_BATCH_DELAY_SEC\" -gt 0 ] && [ \"$START_BATCH_LAUNCHED\" -lt \"$START_BATCH_TOTAL\" ] && [ \"$((START_BATCH_LAUNCHED % START_BATCH_SIZE))\" -eq 0 ]; then".to_string(),
            "    sleep \"$START_BATCH_DELAY_SEC\"".to_string(),
            "  fi".to_string(),
            "done".to_string(),
        ],
    )?;
    write_script(
        &out.join("stop_clab.sh"),
        vec![
            "#!/usr/bin/env bash".to_string(),
            "set -euo pipefail".to_string(),
            "cd \"$(dirname \"$0\")\"".to_string(),
            "cat > active_signal.json <<'JSON'".to_string(),
            stop_signal.trim_end().to_string(),
            "JSON".to_string(),
            "sleep 1".to_string(),
            format!("CONTAINER_PREFIX={}", q(&container_prefix)),
            format!("for n in {node_list}; do"),
            "  docker exec \"${CONTAINER_PREFIX}${n}\" sh -lc \"if [ -f /savop/lab/${n}/supervisor.pid ]; then kill \\$(cat /savop/lab/${n}/supervisor.pid) 2>/dev/null || true; rm -f /savop/lab/${n}/supervisor.pid; fi; if [ -f /savop/lab/${n}/bird.pid ]; then kill \\$(cat /savop/lab/${n}/bird.pid) 2>/dev/null || true; rm -f /savop/lab/${n}/bird.pid; fi\" >/dev/null 2>&1 || true".to_string(),
            "done".to_string(),
        ],
    )?;
    write_script(
        &out.join("status_clab.sh"),
        vec![
            "#!/usr/bin/env bash".to_string(),
            "set -euo pipefail".to_string(),
            "cd \"$(dirname \"$0\")\"".to_string(),
            "./prepare_libs.sh >/dev/null".to_string(),
            format!("CONTAINER_PREFIX={}", q(&container_prefix)),
            format!("for n in {node_list}; do"),
            "  echo \"=== r${n} ===\"".to_string(),
            "  docker exec \"${CONTAINER_PREFIX}${n}\" env LD_LIBRARY_PATH=/savop/lab/lib /savop/lab/birdc -s \"/savop/lab/${n}/bird.ctl\" show protocols || true".to_string(),
            "done".to_string(),
        ],
    )?;
    write_script(
        &out.join("destroy_clab.sh"),
        vec![
            "#!/usr/bin/env bash".to_string(),
            "set -euo pipefail".to_string(),
            "cd \"$(dirname \"$0\")\"".to_string(),
            "./stop_clab.sh >/dev/null 2>&1 || true".to_string(),
            "containerlab destroy -t topology.clab.yml --cleanup >/dev/null 2>&1 || true"
                .to_string(),
        ],
    )?;
    write_script(
        &out.join("prepare_libs.sh"),
        prepare_libs_script(CLAB_IMAGE),
    )?;
    fs::write(
        out.join("multihost_hosts.example.json"),
        serde_json::to_string_pretty(&json!({
            "note": "containerlab artifacts are single-host; use generated topology.clab.yml as the base for multihost partitioning",
            "lab_name": lab_name,
            "agent_mode": agent_mode,
            "bird_debug": bird_debug,
        }))? + "\n",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn link_ips_are_stable_for_ipv4_and_ipv6() {
        assert_eq!(
            link_ips(1, 4),
            ("10.0.0.5".to_string(), "10.0.0.6".to_string())
        );
        assert_eq!(
            link_ips(2, 6),
            ("fec::2:1".to_string(), "fec::2:2".to_string())
        );
        assert_eq!(link_prefix_len(4), 30);
        assert_eq!(link_prefix_len(6), 124);
    }

    #[test]
    fn infer_ip_version_prefers_explicit_config() {
        let base = json!({"auto_ip_version": 4, "devices": {"1": {"prefixes": ["2001:db8::/64"]}}});
        assert_eq!(infer_ip_version(&base), 4);
    }

    #[test]
    fn infer_ip_version_uses_first_available_prefix() {
        let v4_base = json!({"devices": {"1": {"prefixes": ["10.0.0.0/24"]}}});
        let v6_base = json!({"devices": {"1": {"prefixes": ["2001:db8::/64"]}}});
        assert_eq!(infer_ip_version(&v4_base), 4);
        assert_eq!(infer_ip_version(&v6_base), 6);
    }

    #[test]
    fn prefix_items_normalize_ipv6_text() {
        let node = json!({"prefixes": ["FEC::1/64", "10.0.0.0/24"]});
        let prefixes = prefix_items(&node);
        assert!(prefixes.contains_key("fec::/64"));
        assert!(prefixes.contains_key("10.0.0.0/24"));
    }
}
