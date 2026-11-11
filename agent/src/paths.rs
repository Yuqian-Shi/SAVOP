use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct SavopLayout {
    pub root: PathBuf,
    pub agent_dir: PathBuf,
    pub lab_dir: PathBuf,
    pub router_dir: PathBuf,
    pub config_dir: PathBuf,
    pub results_dir: PathBuf,
    pub raw_topology_dir: PathBuf,
    pub itdk_slice_dir: PathBuf,
    pub run_dir: PathBuf,
    pub bench_work_dir: PathBuf,
}

impl SavopLayout {
    pub fn load() -> Result<Self, String> {
        let root = find_root()?;
        Ok(Self::from_root(root))
    }

    pub fn from_root(root: PathBuf) -> Self {
        let values = read_layout_values(&root.join("savop.toml"));
        Self {
            agent_dir: layout_path(&root, &values, "agent_dir", "agent"),
            lab_dir: layout_path(&root, &values, "lab_dir", "lab"),
            router_dir: layout_path(&root, &values, "router_dir", "router"),
            config_dir: layout_path(&root, &values, "config_dir", "lab/base_configs"),
            results_dir: layout_path(&root, &values, "results_dir", "lab/results"),
            raw_topology_dir: layout_path(
                &root,
                &values,
                "raw_topology_dir",
                "lab/data/topologies/raw",
            ),
            itdk_slice_dir: layout_path(
                &root,
                &values,
                "itdk_slice_dir",
                "lab/base_configs/itdk_slices",
            ),
            run_dir: layout_path(&root, &values, "run_dir", "savop_run_clab"),
            bench_work_dir: layout_path(&root, &values, "bench_work_dir", "savop_run_bench"),
            root,
        }
    }

    pub fn resolve_binary(&self, name: &str) -> PathBuf {
        let exe_name = exe_name(name);
        let mut candidates = Vec::new();
        if let Ok(exe) = env::current_exe() {
            if let Some(parent) = exe.parent() {
                candidates.push(parent.join(&exe_name));
            }
        }
        candidates.push(self.root.join("target").join("release").join(&exe_name));
        candidates.extend(path_candidates(&exe_name));
        candidates
            .into_iter()
            .find(|path| path.exists())
            .unwrap_or_else(|| self.root.join("target").join("release").join(exe_name))
    }

    pub fn resolve_config_arg(&self, raw: &str) -> PathBuf {
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            return path;
        }
        let from_root = self.root.join(&path);
        if from_root.exists() {
            return from_root;
        }
        self.config_dir.join(path)
    }

    pub fn resolve_root_arg(&self, raw: &str) -> PathBuf {
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        }
    }

    pub fn print(&self) {
        println!("root={}", self.root.display());
        println!("agent_dir={}", self.agent_dir.display());
        println!("lab_dir={}", self.lab_dir.display());
        println!("router_dir={}", self.router_dir.display());
        println!("config_dir={}", self.config_dir.display());
        println!("results_dir={}", self.results_dir.display());
        println!("raw_topology_dir={}", self.raw_topology_dir.display());
        println!("itdk_slice_dir={}", self.itdk_slice_dir.display());
        println!("run_dir={}", self.run_dir.display());
        println!("bench_work_dir={}", self.bench_work_dir.display());
    }
}

pub fn find_root() -> Result<PathBuf, String> {
    if let Some(root) = env::var_os("SAVOP_ROOT")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return Ok(root);
    }
    if let Ok(cwd) = env::current_dir() {
        if let Some(root) = find_root_from(&cwd) {
            return Ok(root);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(root) = find_root_from(parent) {
                return Ok(root);
            }
        }
    }
    Err("could not locate SAVOP root; run from the repo or set SAVOP_ROOT".to_string())
}

fn find_root_from(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        if ancestor.join("savop.toml").is_file()
            || (ancestor.join("agent").is_dir()
                && ancestor.join("lab").is_dir()
                && ancestor.join("router").is_dir())
        {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn read_layout_values(path: &Path) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return values;
    };
    let mut in_layout = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_layout = line == "[layout]";
            continue;
        }
        if !in_layout {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(
            key.trim().to_string(),
            strip_quotes(value.trim()).to_string(),
        );
    }
    values
}

fn strip_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

fn layout_path(
    root: &Path,
    values: &BTreeMap<String, String>,
    key: &str,
    default: &str,
) -> PathBuf {
    let raw = values.get(key).map(String::as_str).unwrap_or(default);
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn path_candidates(exe_name: &str) -> Vec<PathBuf> {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join(exe_name))
        .collect()
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}
