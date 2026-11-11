"""Validate bounded evidence roots without requiring a machine-specific mount."""
import os
from pathlib import Path


def evidence_parent():
    """The caller selects an existing data-disk directory; never creates it."""
    raw = Path(os.environ.get("SAVOP_EVIDENCE_PARENT", "/mnt/hdd"))
    if not raw.is_absolute() or ".." in raw.parts:
        raise ValueError("SAVOP_EVIDENCE_PARENT must be an absolute path without '..'")
    parent = raw.resolve(strict=True)
    if not parent.is_dir() or parent == Path("/"):
        raise ValueError("Use a dedicated existing evidence parent, not filesystem root")
    return parent


def validate_evidence_root(root, prefix, *, must_exist=True):
    raw = Path(root)
    if not raw.is_absolute() or ".." in raw.parts or raw.is_symlink():
        raise ValueError("Evidence root must be absolute, without symlinks or '..'")
    parent = evidence_parent()
    if raw.parent.resolve(strict=True) != parent or not raw.name.startswith(prefix):
        raise ValueError(f"Use a dedicated {parent}/{prefix}* directory")
    resolved = raw.resolve(strict=must_exist)
    if must_exist and not resolved.is_dir():
        raise ValueError("Evidence root is not a directory")
    if not must_exist and resolved.exists():
        raise ValueError("Evidence root already exists; refusing reuse")
    return resolved
