"""Git operations — clone, pull, diff, and file scanning."""

import logging
import os
import shutil
from pathlib import Path

import git

from .config import GITHUB_DIR, IGNORE_DIRS, SIGMA_EXTENSIONS, YARA_EXTENSIONS

logger = logging.getLogger(__name__)


def repo_name_from_url(url: str) -> str:
    """Derive a unique folder name like 'Neo23x0_signature-base' from a git URL."""
    clean = url.rstrip("/")
    if clean.endswith(".git"):
        clean = clean[:-4]
    parts = clean.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}_{parts[-1]}"
    return parts[-1]


def clone_or_pull(url: str, dest: Path) -> tuple[git.Repo, bool]:
    """Clone a repo or pull updates. Returns (repo, is_new_clone)."""
    if dest.exists():
        try:
            repo = git.Repo(str(dest))
        except git.InvalidGitRepositoryError:
            logger.warning("Corrupt repo at %s — re-cloning", dest)
            shutil.rmtree(dest)
            repo = git.Repo.clone_from(url, str(dest))
            return repo, True

        try:
            repo.remotes.origin.pull()
        except Exception as exc:
            logger.warning("git pull failed (%s): %s", dest.name, exc)

        return repo, False

    dest.parent.mkdir(parents=True, exist_ok=True)
    repo = git.Repo.clone_from(url, str(dest))
    return repo, True


# ── File classification ────────────────────────────────────────────


def _is_ignored(rel_path: str) -> bool:
    return any(part in IGNORE_DIRS for part in Path(rel_path).parts)


def classify_file(rel_path: str, repo_type: str) -> str | None:
    """Return 'yara', 'sigma', or None based on extension and repo type.

    Actual content validation is deferred to the parsers.
    """
    if _is_ignored(rel_path):
        return None

    ext = Path(rel_path).suffix.lower()

    if ext in YARA_EXTENSIONS and repo_type in ("yara", "both"):
        return "yara"

    if ext in SIGMA_EXTENSIONS and repo_type in ("sigma", "both"):
        return "sigma"

    return None


# ── Scanning ───────────────────────────────────────────────────────


def scan_all_rule_files(repo_root: Path, repo_type: str) -> list[str]:
    """Walk the cloned repo and return relative paths of candidate rule files."""
    results: list[str] = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo_root)
            if classify_file(rel, repo_type) is not None:
                results.append(rel)
    return results


def changed_files_between(
    repo: git.Repo,
    old_hash: str,
    new_hash: str,
) -> tuple[list[str], list[str]]:
    """Diff two commits and return (added_or_modified, deleted) relative paths."""
    diffs = repo.commit(old_hash).diff(repo.commit(new_hash))
    added_mod: list[str] = []
    deleted: list[str] = []

    for d in diffs:
        if d.change_type in ("A", "M", "C"):
            added_mod.append(d.b_path)
        elif d.change_type == "R":
            added_mod.append(d.b_path)
            deleted.append(d.a_path)
        elif d.change_type == "D":
            deleted.append(d.a_path)

    return added_mod, deleted
