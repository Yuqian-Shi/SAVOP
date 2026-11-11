use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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
    netns_dir: PathBuf,
    netns_prefix: String,
    nodes: Vec<String>,
    jobs: usize,
    timeout_ms: u64,
    hash_mode: HashMode,
}

#[derive(Clone)]
struct ProbeResult {
    node: String,
    raw_hash: String,
    rib_hash: String,
    fib_hash: String,
    combo_hash: String,
}

#[derive(Clone, Copy)]
enum HashMode {
    Sorted,
    Ordered,
}

fn usage() -> ! {
    eprintln!(
        "usage: sav_route_probe --netns-dir DIR --netns-prefix PREFIX [--jobs N] [--timeout-ms MS] [--hash-mode sorted|ordered] --nodes NODE [NODE ...]"
    );
    std::process::exit(2);
}

fn parse_args() -> Config {
    let mut args = env::args().skip(1);
    let mut netns_dir = None;
    let mut netns_prefix = None;
    let mut nodes = Vec::new();
    let mut jobs = 8_usize;
    let mut timeout_ms = 5000_u64;
    let mut hash_mode = HashMode::Sorted;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--netns-dir" => netns_dir = args.next().map(PathBuf::from),
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
            "--hash-mode" => {
                hash_mode = match args.next().as_deref() {
                    Some("sorted") => HashMode::Sorted,
                    Some("ordered") => HashMode::Ordered,
                    _ => usage(),
                };
            }
            "--nodes" => {
                nodes.extend(args.by_ref());
                break;
            }
            value if value.starts_with('-') => usage(),
            value => nodes.push(value.to_string()),
        }
    }

    let Some(netns_dir) = netns_dir else {
        usage();
    };
    let Some(netns_prefix) = netns_prefix else {
        usage();
    };
    if nodes.is_empty() {
        usage();
    }
    if jobs == 0 {
        jobs = 1;
    }

    Config {
        netns_dir,
        netns_prefix,
        nodes,
        jobs,
        timeout_ms,
        hash_mode,
    }
}

struct BirdClient {
    reader: BufReader<UnixStream>,
}

impl BirdClient {
    fn connect(path: &Path, timeout: Duration) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let mut client = Self {
            reader: BufReader::new(stream),
        };
        let _ = client.read_response()?;
        Ok(client)
    }

    fn command(&mut self, command: &str) -> io::Result<Vec<String>> {
        self.reader.get_mut().write_all(command.as_bytes())?;
        self.reader.get_mut().write_all(b"\n")?;
        self.reader.get_mut().flush()?;
        self.read_response()
    }

    fn read_response(&mut self) -> io::Result<Vec<String>> {
        let mut output = Vec::new();
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "BIRD control socket closed",
                ));
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
            output.push(format!("??? <{line}>"));
        }
    }
}

fn semantic_bird_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(close_rel) = bytes[i..].iter().position(|&b| b == b']') {
                let end = i + close_rel;
                let inside = &line[i + 1..end];
                if strip_proto_time(inside).is_some() {
                    out.push_str("[PROTO_TIME]");
                    i = end + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn strip_proto_time(value: &str) -> Option<&str> {
    let split = value.rfind(' ')?;
    let time = &value[split + 1..];
    let b = time.as_bytes();
    if b.len() == 12
        && b[2] == b':'
        && b[5] == b':'
        && b[8] == b'.'
        && b.iter()
            .enumerate()
            .all(|(idx, ch)| matches!(idx, 2 | 5 | 8) || ch.is_ascii_digit())
    {
        Some(&value[..split])
    } else {
        None
    }
}

fn hash_ordered_lines<'a>(lines: impl IntoIterator<Item = &'a String>) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for line in lines {
        for byte in line.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= b'\n' as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn hash_sorted_lines(lines: &[String]) -> String {
    let mut sorted = lines.to_vec();
    sorted.sort_unstable();
    hash_ordered_lines(sorted.iter())
}

fn hash_lines(lines: &[String], mode: HashMode) -> String {
    match mode {
        HashMode::Sorted => hash_sorted_lines(lines),
        HashMode::Ordered => hash_ordered_lines(lines.iter()),
    }
}

fn read_bird_rib(cfg: &Config, node: &str) -> io::Result<(Vec<String>, Vec<String>)> {
    let socket = cfg.netns_dir.join(node).join("bird.ctl");
    let mut client = BirdClient::connect(&socket, Duration::from_millis(cfg.timeout_ms))?;
    let mut raw = Vec::new();
    raw.push("### bird master4".to_string());
    raw.extend(client.command("show route table master4")?);
    raw.push("### bird master6".to_string());
    raw.extend(client.command("show route table master6")?);

    let semantic = raw
        .iter()
        .filter(|line| !line.starts_with("BIRD ") || !line.ends_with(" ready."))
        .map(|line| semantic_bird_line(line))
        .collect();
    Ok((raw, semantic))
}

fn read_kernel_fib(cfg: &Config, node: &str) -> io::Result<Vec<String>> {
    let ns_path = PathBuf::from(format!("/var/run/netns/{}{}", cfg.netns_prefix, node));
    let ns = File::open(ns_path)?;
    let rc = unsafe { setns(ns.as_raw_fd(), CLONE_NEWNET) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut fib = Vec::new();
    fib.push("### proc net route".to_string());
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        fib.extend(content.lines().map(str::to_string));
    }
    fib.push("### proc net ipv6_route".to_string());
    if let Ok(content) = fs::read_to_string("/proc/net/ipv6_route") {
        fib.extend(content.lines().map(str::to_string));
    }
    Ok(fib)
}

fn probe_node(cfg: &Config, node: &str) -> io::Result<ProbeResult> {
    let (raw_rib, sem_rib) = read_bird_rib(cfg, node)?;
    let fib = read_kernel_fib(cfg, node)?;
    let mut combo = sem_rib.clone();
    combo.extend(fib.iter().cloned());

    Ok(ProbeResult {
        node: node.to_string(),
        raw_hash: hash_lines(&raw_rib, cfg.hash_mode),
        rib_hash: hash_lines(&sem_rib, cfg.hash_mode),
        fib_hash: hash_lines(&fib, cfg.hash_mode),
        combo_hash: hash_lines(&combo, cfg.hash_mode),
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
        println!(
            "{},{},{},{},{}",
            result.node, result.raw_hash, result.rib_hash, result.fib_hash, result.combo_hash
        );
    }

    let errors = errors.lock().unwrap();
    if !errors.is_empty() {
        for err in errors.iter() {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}
