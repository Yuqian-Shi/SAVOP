use sav_agent::paths::SavopLayout;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone)]
struct Args {
    layout: SavopLayout,
    itdk_dir: PathBuf,
    out_dir: PathBuf,
    sizes: Vec<usize>,
    candidate_nodes: usize,
    max_hyperedge_members: usize,
    asn_mode: AsnMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AsnMode {
    Unique,
    Itdk,
}

#[derive(Default)]
struct LinkStats {
    scanned: usize,
    used_hyperedges: usize,
    skipped_large_hyperedges: usize,
    star_edges: usize,
}

fn usage() -> ! {
    eprintln!(
        "usage: sav_itdk_slice [--itdk-dir PATH] [--out-dir PATH] [--sizes 500,1000,4000] [--candidate-nodes N] [--max-hyperedge-members N] [--asn-mode unique|itdk]"
    );
    std::process::exit(2);
}

fn main() -> io::Result<()> {
    let args = parse_args();
    fs::create_dir_all(&args.out_dir)?;

    eprintln!("loading ITDK router set from {}", args.itdk_dir.display());
    let router_as = load_router_as(&args.itdk_dir.join("midar-iff-snmp.routers.bz2"))?;
    eprintln!("router entries with AS: {}", router_as.len());

    let max_size = *args.sizes.iter().max().unwrap_or(&4000);
    let wanted_candidates = args.candidate_nodes.max(max_size * 4);
    eprintln!("streaming links until at least {wanted_candidates} candidate routers are connected");
    let (adj, stats) = load_candidate_graph(
        &args.itdk_dir.join("midar-iff-snmp.links.bz2"),
        &router_as,
        wanted_candidates,
        args.max_hyperedge_members,
    )?;
    eprintln!(
        "links scanned={} used_hyperedges={} expanded_edges={} skipped_large_hyperedges={} candidate_nodes={}",
        stats.scanned,
        stats.used_hyperedges,
        stats.star_edges,
        stats.skipped_large_hyperedges,
        adj.len()
    );

    let component = largest_component(&adj);
    if component.len() < max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "largest component has {} routers, smaller than requested {max_size}; increase --candidate-nodes",
                component.len()
            ),
        ));
    }
    let ordered = bfs_order(&adj, &component, max_size);
    if ordered.len() < max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("BFS selected only {} routers", ordered.len()),
        ));
    }

    let metadata = json!({
        "source": "CAIDA ITDK 2025-03 midar-iff-snmp",
        "source_dir": portable_path(&args.itdk_dir, &args.layout.root),
        "conversion": {
            "node_filter": "midar-iff-snmp.routers.bz2 node2id entries",
            "link_expansion": "path over each IP-layer link/hyperedge",
            "max_hyperedge_members": args.max_hyperedge_members,
            "asn_mode": match args.asn_mode { AsnMode::Unique => "unique", AsnMode::Itdk => "itdk" },
            "candidate_nodes": wanted_candidates,
            "candidate_graph_nodes": adj.len(),
            "largest_component_nodes": component.len(),
            "links_scanned": stats.scanned,
            "used_hyperedges": stats.used_hyperedges,
            "expanded_edges": stats.star_edges,
            "skipped_large_hyperedges": stats.skipped_large_hyperedges
        }
    });

    let mut summary = String::from("file,nodes,links,candidate_graph_nodes,largest_component_nodes,links_scanned,expanded_edges,skipped_large_hyperedges,asn_mode\n");
    for size in &args.sizes {
        let selected = &ordered[..*size];
        let config = build_config(selected, &adj, &router_as, args.asn_mode, &metadata);
        let links = config
            .get("links")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let file_name = format!("itdk_midar_iff_snmp_{size}_routers_v4.json");
        let out_path = args.out_dir.join(&file_name);
        let text = serde_json::to_string_pretty(&config)?;
        fs::write(&out_path, text)?;
        summary.push_str(&format!(
            "{file_name},{size},{links},{},{},{},{},{},{}\n",
            adj.len(),
            component.len(),
            stats.scanned,
            stats.star_edges,
            stats.skipped_large_hyperedges,
            match args.asn_mode {
                AsnMode::Unique => "unique",
                AsnMode::Itdk => "itdk",
            }
        ));
        eprintln!(
            "wrote {} nodes / {} links to {}",
            size,
            links,
            out_path.display()
        );
    }
    fs::write(args.out_dir.join("itdk_slice_summary.csv"), summary)?;
    Ok(())
}

fn parse_args() -> Args {
    let layout = load_layout_or_exit();
    let mut itdk_dir = layout.raw_topology_dir.join("caida_itdk/2025-03");
    let mut out_dir = layout.itdk_slice_dir.clone();
    let mut sizes = vec![500, 800, 1000, 1200, 1500, 2000, 3000, 4000];
    let mut candidate_nodes = 20_000;
    let mut max_hyperedge_members = 64;
    let mut asn_mode = AsnMode::Unique;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--itdk-dir" => itdk_dir = layout.resolve_root_arg(&next_arg(&mut args)),
            "--out-dir" => out_dir = layout.resolve_root_arg(&next_arg(&mut args)),
            "--sizes" => sizes = parse_sizes(&next_arg(&mut args)),
            "--candidate-nodes" => {
                candidate_nodes = next_arg(&mut args).parse().unwrap_or_else(|_| usage())
            }
            "--max-hyperedge-members" => {
                max_hyperedge_members = next_arg(&mut args).parse().unwrap_or_else(|_| usage())
            }
            "--asn-mode" => {
                asn_mode = match next_arg(&mut args).as_str() {
                    "unique" => AsnMode::Unique,
                    "itdk" => AsnMode::Itdk,
                    _ => usage(),
                }
            }
            _ => usage(),
        }
    }

    if sizes.is_empty() {
        usage();
    }
    sizes.sort_unstable();
    sizes.dedup();

    Args {
        layout,
        itdk_dir,
        out_dir,
        sizes,
        candidate_nodes,
        max_hyperedge_members,
        asn_mode,
    }
}

fn next_arg(args: &mut impl Iterator<Item = String>) -> String {
    args.next().unwrap_or_else(|| usage())
}

fn parse_sizes(raw: &str) -> Vec<usize> {
    raw.split(',')
        .filter_map(|item| item.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .collect()
}

fn load_layout_or_exit() -> SavopLayout {
    SavopLayout::load().unwrap_or_else(|err| {
        eprintln!("error: {err}");
        std::process::exit(1);
    })
}

fn portable_path(path: &Path, run_root: &Path) -> String {
    let absolute_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let absolute_root = run_root
        .canonicalize()
        .unwrap_or_else(|_| run_root.to_path_buf());

    absolute_path
        .strip_prefix(&absolute_root)
        .map(|relative| relative.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn bz_lines(path: &Path) -> io::Result<impl Iterator<Item = io::Result<String>>> {
    let mut child = Command::new("bzcat")
        .arg(path)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("bzcat stdout unavailable"))?;
    Ok(BufReader::new(stdout).lines())
}

fn load_router_as(path: &Path) -> io::Result<HashMap<u64, u64>> {
    let mut router_as = HashMap::new();
    let mut current_id = None;
    for line in bz_lines(path)? {
        let line = line?;
        if let Some(value) = line.strip_prefix("# node2id:") {
            current_id = value.trim().parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("# node2as:") {
            if let (Some(id), Ok(asn)) = (current_id, value.trim().parse::<u64>()) {
                router_as.insert(id, asn);
            }
        }
    }
    Ok(router_as)
}

fn load_candidate_graph(
    path: &Path,
    router_as: &HashMap<u64, u64>,
    candidate_nodes: usize,
    max_hyperedge_members: usize,
) -> io::Result<(HashMap<u64, HashSet<u64>>, LinkStats)> {
    let mut adj: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut stats = LinkStats::default();

    for line in bz_lines(path)? {
        let line = line?;
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        stats.scanned += 1;
        let mut members = Vec::new();
        for token in line.split_whitespace().skip(2) {
            if let Some(id) = parse_node_id(token) {
                if router_as.contains_key(&id) {
                    members.push(id);
                }
            }
        }
        members.sort_unstable();
        members.dedup();
        if members.len() < 2 {
            continue;
        }
        if members.len() > max_hyperedge_members {
            stats.skipped_large_hyperedges += 1;
            continue;
        }

        stats.used_hyperedges += 1;
        for pair in members.windows(2) {
            add_edge(&mut adj, pair[0], pair[1]);
            stats.star_edges += 1;
        }
        if adj.len() >= candidate_nodes {
            break;
        }
    }
    Ok((adj, stats))
}

fn parse_node_id(token: &str) -> Option<u64> {
    let raw = token.split_once(':').map(|(node, _)| node).unwrap_or(token);
    let digits = raw.strip_prefix('N')?;
    digits.parse::<u64>().ok()
}

fn add_edge(adj: &mut HashMap<u64, HashSet<u64>>, a: u64, b: u64) {
    if a == b {
        return;
    }
    adj.entry(a).or_default().insert(b);
    adj.entry(b).or_default().insert(a);
}

fn largest_component(adj: &HashMap<u64, HashSet<u64>>) -> Vec<u64> {
    let mut seen = HashSet::new();
    let mut best = Vec::new();
    for start in adj.keys().copied() {
        if seen.contains(&start) {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = VecDeque::from([start]);
        seen.insert(start);
        while let Some(node) = queue.pop_front() {
            component.push(node);
            if let Some(neighbors) = adj.get(&node) {
                for next in neighbors {
                    if seen.insert(*next) {
                        queue.push_back(*next);
                    }
                }
            }
        }
        if component.len() > best.len() {
            best = component;
        }
    }
    best
}

fn bfs_order(adj: &HashMap<u64, HashSet<u64>>, component: &[u64], limit: usize) -> Vec<u64> {
    let component_set: HashSet<u64> = component.iter().copied().collect();
    let Some(start) = component.iter().copied().max_by_key(|id| degree(adj, *id)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::from([start]);
    let mut queue = VecDeque::from([start]);
    while let Some(node) = queue.pop_front() {
        out.push(node);
        if out.len() >= limit {
            break;
        }
        let mut neighbors: Vec<u64> = adj
            .get(&node)
            .into_iter()
            .flat_map(|items| items.iter().copied())
            .filter(|id| component_set.contains(id) && !seen.contains(id))
            .collect();
        neighbors.sort_by_key(|id| std::cmp::Reverse(degree(adj, *id)));
        for next in neighbors {
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    out
}

fn degree(adj: &HashMap<u64, HashSet<u64>>, id: u64) -> usize {
    adj.get(&id).map(HashSet::len).unwrap_or(0)
}

fn build_config(
    selected: &[u64],
    adj: &HashMap<u64, HashSet<u64>>,
    router_as: &HashMap<u64, u64>,
    asn_mode: AsnMode,
    metadata: &Value,
) -> Value {
    let selected_set: HashSet<u64> = selected.iter().copied().collect();
    let id_map: HashMap<u64, usize> = selected
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, original)| (original, idx + 1))
        .collect();

    let mut devices = Map::new();
    for (idx, original_id) in selected.iter().copied().enumerate() {
        let node_id = idx + 1;
        let asn = match asn_mode {
            AsnMode::Unique => 64512 + node_id as u64,
            AsnMode::Itdk => router_as
                .get(&original_id)
                .copied()
                .unwrap_or(64512 + node_id as u64),
        };
        let prefix = synthetic_prefix(node_id);
        let mut prefixes = Map::new();
        prefixes.insert(
            prefix,
            json!({
                "miig_tag": 0,
                "miig_type": 1
            }),
        );
        devices.insert(
            node_id.to_string(),
            json!({
                "as": asn,
                "itdk_node": format!("N{original_id}"),
                "itdk_as": router_as.get(&original_id).copied(),
                "prefixes": Value::Object(prefixes)
            }),
        );
    }

    let mut links = Vec::new();
    for original in selected {
        let src = id_map[original];
        if let Some(neighbors) = adj.get(original) {
            for peer in neighbors {
                if !selected_set.contains(peer) {
                    continue;
                }
                let dst = id_map[peer];
                if src < dst {
                    links.push(json!([src.to_string(), dst.to_string(), "dsav"]));
                }
            }
        }
    }
    links.sort_by_key(|value| {
        let arr = value.as_array().unwrap();
        let a = arr[0].as_str().unwrap().parse::<usize>().unwrap_or(0);
        let b = arr[1].as_str().unwrap().parse::<usize>().unwrap_or(0);
        (a, b)
    });

    json!({
        "sav_apps": [],
        "active_sav_app": null,
        "devices": Value::Object(devices),
        "links": links,
        "as_relations": {
            "description": "ITDK router-level synthetic eBGP slice; provider-customer relations intentionally empty.",
            "provider-customer": []
        },
        "enable_rpki": false,
        "prefix_method": "blackhole",
        "auto_ip_version": 4,
        "ignore_irrelevant_nets": true,
        "ignore_private": false,
        "metadata": metadata
    })
}

fn synthetic_prefix(node_id: usize) -> String {
    let offset = node_id as u32;
    let second = 18 + ((offset >> 16) & 0x01);
    let third = (offset >> 8) & 0xff;
    let fourth = offset & 0xff;
    format!("198.{second}.{third}.{fourth}/32")
}
