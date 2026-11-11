//! Accidental-loss protection, not a sandbox against concurrent hostile writers.
//! Generation is new-directory-only: no existing files or directories are removed.

use sav_agent::paths::SavopLayout;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const MANIFEST: &str = ".savop-output.json";

fn refuse(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(refuse("empty paths and '..' components are not allowed"));
    }
    std::path::absolute(path)
}

fn remap_root(path: &Path, logical: &Path, canonical: &Path) -> io::Result<PathBuf> {
    let path = absolute(path)?;
    Ok(match path.strip_prefix(logical) {
        Ok(relative) => canonical.join(relative),
        Err(_) => path,
    })
}

fn protected(path: &Path, root: &Path, layout: &SavopLayout) -> io::Result<bool> {
    if root.starts_with(path) {
        return Ok(true);
    }
    let logical_root = absolute(&layout.root)?;
    let mut sources = vec![
        layout.agent_dir.clone(),
        layout.lab_dir.clone(),
        layout.router_dir.clone(),
        layout.config_dir.clone(),
        layout.results_dir.clone(),
        layout.raw_topology_dir.clone(),
        layout.itdk_slice_dir.clone(),
    ];
    for name in [".git", ".cargo", "savop_demo", "archive", "DELETE"] {
        sources.push(root.join(name));
    }
    if let Some(workspace) = root.parent() {
        sources.extend([workspace.join("archive"), workspace.join("DELETE")]);
    }
    for source in sources {
        let source = remap_root(&source, &logical_root, root)?;
        if path.starts_with(&source) || source.starts_with(path) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve and check a destination without writing anything.
pub(super) fn validate_destination(layout: &SavopLayout, requested: &Path) -> io::Result<PathBuf> {
    let logical_root = absolute(&layout.root)?;
    let root = fs::canonicalize(&layout.root)?;
    let out = remap_root(requested, &logical_root, &root)?;
    if protected(&out, &root, layout)? {
        return Err(refuse(format!("protected output path: {}", out.display())));
    }

    // Preserve documented savop_run_* examples and explicitly configured run roots.
    let conventional = out.strip_prefix(&root).ok().is_some_and(|relative| {
        relative.components().next().is_some_and(|part| {
            part.as_os_str().to_str().is_some_and(|name| {
                name.starts_with("savop_run_") && name.len() > "savop_run_".len()
            })
        })
    });
    let mut configured = false;
    for scope in [&layout.run_dir, &layout.bench_work_dir] {
        let scope = remap_root(scope, &logical_root, &root)?;
        if !protected(&scope, &root, layout)? && out.starts_with(&scope) {
            configured = true;
        }
    }
    if !conventional && !configured {
        return Err(refuse(
            "output must be under a repository savop_run_* directory or a configured run_dir/bench_work_dir",
        ));
    }

    // symlink_metadata also sees dangling links. Do not follow any untrusted
    // output component, including an otherwise valid run-directory symlink.
    let mut current = PathBuf::new();
    for component in out.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(refuse(format!(
                        "output path contains a symlink or non-directory: {}",
                        current.display()
                    )));
                }
                if current == out {
                    return Err(refuse(format!(
                        "output already exists; preserve it and choose a new path: {}",
                        out.display()
                    )));
                }
                if fs::symlink_metadata(current.join(MANIFEST)).is_ok() {
                    return Err(refuse(
                        "cannot nest output inside an existing generated lab",
                    ));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(out)
}

/// Recheck immediately before creating; create_dir refuses an existing leaf.
pub(super) fn create_destination(layout: &SavopLayout, requested: &Path) -> io::Result<()> {
    let out = validate_destination(layout, requested)?;
    let parent = out
        .parent()
        .ok_or_else(|| refuse("output needs a parent"))?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&current)?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(refuse("output parent changed; refusing generation"));
                }
            }
            Err(err) => return Err(err),
        }
    }
    fs::create_dir(out)
}

pub(super) fn write_manifest(out: &Path, config: &Path) -> io::Result<()> {
    fn inventory(base: &Path, dir: &Path, files: &mut Vec<String>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                inventory(base, &entry.path(), files)?;
            } else if kind.is_file() {
                files.push(
                    entry
                        .path()
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            } else {
                return Err(refuse("unexpected non-regular generated artifact"));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    inventory(out, out, &mut files)?;
    files.sort();
    let manifest = json!({
        "schema_version": 1,
        "generator": "sav_lab_gen",
        "state": "generated",
        "config": fs::canonicalize(config)?,
        "output": out,
        "files": files,
        "note": "Generation only; does not certify deployment or authorize deletion/overwrite."
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join(MANIFEST))?;
    writeln!(file, "{}", serde_json::to_string_pretty(&manifest)?)
}
