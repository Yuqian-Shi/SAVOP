//! CLI regression tests. All writes are confined to uniquely owned temp fixtures;
//! router binaries are inert placeholder files and no generated script is run.

use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    temp: PathBuf,
    root: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = parent.join(format!(
            "savop-output-protection-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&temp).unwrap();
        let root = temp.join("repo");
        fs::create_dir(&root).unwrap();
        for dir in ["agent", "lab", "router", ".git", "savop_demo", "archive"] {
            fs::create_dir(root.join(dir)).unwrap();
        }
        for name in ["bird", "birdc", "birdcl"] {
            fs::write(
                root.join("router").join(name),
                b"inert test fixture; never executed",
            )
            .unwrap();
        }
        fs::write(root.join("savop.toml"), "[layout]\n").unwrap();
        let config = root.join("lab/input.json");
        let fixture = Self { temp, root, config };
        fixture.set_config(valid_config());
        fixture
    }

    fn set_config(&self, value: Value) {
        fs::write(&self.config, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn command(&self, out: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sav_lab_gen"));
        cmd.current_dir(&self.root)
            .env("SAVOP_ROOT", &self.root)
            .arg("--config")
            .arg(&self.config)
            .arg("--out")
            .arg(out);
        cmd
    }

    fn run(&self, out: &Path) -> Output {
        self.command(out).output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        assert_eq!(self.temp.parent(), Some(parent.as_path()));
        assert!(self
            .temp
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("savop-output-protection-"));
        assert!(!fs::symlink_metadata(&self.temp)
            .unwrap()
            .file_type()
            .is_symlink());
        // Only the unique fixture allocated above; never a user-supplied path.
        fs::remove_dir_all(&self.temp).unwrap();
    }
}

fn valid_config() -> Value {
    json!({
        "auto_ip_version": 4,
        "devices": {
            "1": {"as": 65001, "prefixes": ["192.0.2.0/24"]},
            "2": {"as": 65002, "prefixes": ["198.51.100.0/24"]}
        },
        "links": [["1", "2", "dsav"]]
    })
}

fn assert_failure(result: Output, message: &str) {
    assert!(!result.status.success(), "unexpected success");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(message),
        "expected {message:?}, got {stderr}"
    );
}

#[test]
fn new_output_generates_artifacts_and_ownership_manifest() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_safe/trial");
    let result = f.run(&out);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join(".savop-output.json")).unwrap()).unwrap();
    assert_eq!(manifest["generator"], "sav_lab_gen");
    assert_eq!(manifest["state"], "generated");
    let files = manifest["files"].as_array().unwrap();
    assert!(files.contains(&json!("1/bird.conf")));
    assert!(files.contains(&json!("topology.clab.yml")));
    for item in files {
        assert!(out.join(item.as_str().unwrap()).is_file());
    }
}

#[test]
fn existing_unmarked_output_and_results_are_untouched() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_old");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("results.csv"), b"valuable old results").unwrap();
    assert_failure(f.run(&out), "output already exists");
    assert_eq!(
        fs::read(out.join("results.csv")).unwrap(),
        b"valuable old results"
    );
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
}

#[test]
fn existing_marked_output_is_not_authorization_to_overwrite() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_done");
    assert!(f.run(&out).status.success());
    let before = fs::read(out.join(".savop-output.json")).unwrap();
    fs::write(out.join("results.csv"), b"keep").unwrap();
    assert_failure(f.run(&out), "output already exists");
    assert_eq!(fs::read(out.join(".savop-output.json")).unwrap(), before);
    assert_eq!(fs::read(out.join("results.csv")).unwrap(), b"keep");
}

#[test]
fn existing_empty_directory_is_preserved() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_empty");
    fs::create_dir(&out).unwrap();
    assert_failure(f.run(&out), "output already exists");
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
}

#[test]
fn repository_ancestors_sources_and_archives_are_rejected() {
    let f = Fixture::new();
    let before = fs::read(&f.config).unwrap();
    for out in [
        f.root.clone(),
        f.temp.clone(),
        PathBuf::from("/"),
        f.root.join("agent/new"),
        f.root.join("lab/new"),
        f.root.join("router/new"),
        f.root.join(".git/new"),
        f.root.join("savop_demo/new"),
        f.root.join("archive/new"),
        f.temp.join("archive/new"),
    ] {
        assert_failure(f.run(&out), "protected output path");
    }
    assert_eq!(fs::read(&f.config).unwrap(), before);
    assert!(!f.root.join("agent/new").exists());
    assert!(!f.temp.join("archive").exists());
}

#[test]
fn parent_traversal_is_rejected_without_writes() {
    let f = Fixture::new();
    assert_failure(f.run(&f.root.join("savop_run_new/../escaped")), "'..'");
    assert!(!f.root.join("savop_run_new").exists());
    assert!(!f.root.join("escaped").exists());
}

#[test]
fn unconfigured_destination_is_rejected() {
    let f = Fixture::new();
    for out in [f.temp.join("elsewhere"), f.root.join("unexpected")] {
        assert_failure(f.run(&out), "output must be under");
        assert!(!out.exists());
    }
}

#[test]
fn symlink_output_does_not_touch_target() {
    let f = Fixture::new();
    let target = f.temp.join("valuable");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("keep"), b"original").unwrap();
    let out = f.root.join("savop_run_link");
    symlink(&target, &out).unwrap();
    assert_failure(f.run(&out), "symlink or non-directory");
    assert_eq!(fs::read(target.join("keep")).unwrap(), b"original");
    assert!(fs::symlink_metadata(out).unwrap().file_type().is_symlink());
}

#[test]
fn dangling_output_symlink_is_rejected() {
    let f = Fixture::new();
    let target = f.temp.join("missing");
    let out = f.root.join("savop_run_dangling");
    symlink(&target, &out).unwrap();
    assert_failure(f.run(&out), "symlink or non-directory");
    assert!(!target.exists());
}

#[test]
fn symlink_parent_cannot_redirect_writes() {
    let f = Fixture::new();
    let target = f.temp.join("external");
    fs::create_dir(&target).unwrap();
    symlink(&target, f.root.join("savop_run_link")).unwrap();
    assert_failure(
        f.run(&f.root.join("savop_run_link/child")),
        "symlink or non-directory",
    );
    assert_eq!(fs::read_dir(target).unwrap().count(), 0);
}

#[test]
fn output_file_is_never_overwritten() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_file");
    fs::write(&out, b"keep file").unwrap();
    assert_failure(f.run(&out), "symlink or non-directory");
    assert_eq!(fs::read(out).unwrap(), b"keep file");
}

#[test]
fn invalid_json_creates_no_output() {
    let f = Fixture::new();
    fs::write(&f.config, b"{invalid").unwrap();
    let out = f.root.join("savop_run_invalid");
    assert!(!f.run(&out).status.success());
    assert!(!out.exists());
}

#[test]
fn invalid_links_are_validated_before_creation() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_invalid");
    for links in [
        json!([42]),
        json!([["1", "9", "dsav"]]),
        json!([["1", "2", "bad"]]),
    ] {
        let mut config = valid_config();
        config["links"] = links;
        f.set_config(config);
        assert!(!f.run(&out).status.success());
        assert!(!out.exists());
    }
}

#[test]
fn unsafe_node_ids_cannot_escape_output() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_invalid");
    for id in ["../escape", "/tmp/escape", "1;touch", "01", "0"] {
        f.set_config(json!({"devices": {id: {"as": 65001}}, "links": []}));
        assert_failure(f.run(&out), "node ID must be a positive integer");
        assert!(!out.exists());
    }
    assert!(!f.root.join("escape").exists());
}

#[test]
fn invalid_node_fields_are_validated_before_creation() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_invalid");
    for node in [
        json!({}),
        json!({"as": 0}),
        json!({"as": 4294967296_u64}),
        json!({"as": 65001, "prefixes": ["192.0.2.0/33"]}),
        json!({"as": 65001, "prefixes": ["2001:db8::/129"]}),
        json!({"as": 65001, "prefixes": [false]}),
    ] {
        f.set_config(json!({"devices": {"1": node}, "links": []}));
        assert!(!f.run(&out).status.success());
        assert!(!out.exists());
    }
}

#[test]
fn missing_router_binary_creates_no_output() {
    let f = Fixture::new();
    fs::rename(f.root.join("router/bird"), f.root.join("router/bird.saved")).unwrap();
    let out = f.root.join("savop_run_missing");
    assert!(!f.run(&out).status.success());
    assert!(!out.exists());
}

#[test]
fn configured_external_run_root_is_supported() {
    let f = Fixture::new();
    let run_root = f.temp.join("dedicated-runs");
    fs::write(
        f.root.join("savop.toml"),
        format!("[layout]\nrun_dir = \"{}\"\n", run_root.display()),
    )
    .unwrap();
    let out = run_root.join("trial-1");
    let result = f.run(&out);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(out.join(".savop-output.json").is_file());
}

#[test]
fn configured_run_root_cannot_authorize_source_overwrite() {
    let f = Fixture::new();
    fs::write(f.root.join("savop.toml"), "[layout]\nrun_dir = \"agent\"\n").unwrap();
    assert_failure(f.run(&f.root.join("agent/new")), "protected output path");
    assert!(!f.root.join("agent/new").exists());
}

#[test]
fn nested_generation_inside_completed_lab_is_rejected() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_done");
    assert!(f.run(&out).status.success());
    assert_failure(f.run(&out.join("child")), "cannot nest output");
    assert!(!out.join("child").exists());
}

#[test]
fn concurrent_generators_cannot_claim_same_output() {
    let f = Fixture::new();
    let out = f.root.join("savop_run_concurrent");
    let first = f
        .command(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let second = f
        .command(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let first_ok = first.wait_with_output().unwrap().status.success();
    let second_ok = second.wait_with_output().unwrap().status.success();
    assert_ne!(first_ok, second_ok);
    assert!(out.join(".savop-output.json").is_file());
}
