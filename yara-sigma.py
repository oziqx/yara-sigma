#!/usr/bin/env python3
"""
YARA & Sigma Rule Parser — Orchestrator

Clones/pulls GitHub repos, extracts individual YARA & Sigma rules,
validates them, and saves each rule as a separate JSON file.

Usage:
    python yara-sigma.py
"""

import hashlib
import logging
import logging.handlers
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from modules.config import GITHUB_DIR, OUTPUT_DIR, REPOS
from modules.git_manager import (
    changed_files_between,
    classify_file,
    clone_or_pull,
    repo_name_from_url,
    scan_all_rule_files,
)
from modules.normalizer import normalize_rule
from modules.output_writer import (
    generate_summary,
    print_summary,
    remove_repo_output,
    remove_rules_for_file,
    save_rule,
)
from parsers.sigma_parser import extract_sigma_rules
from parsers.yara_parser import extract_yara_rules
from modules.state_manager import load_state, save_state

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_console = logging.StreamHandler()
_console.setFormatter(_fmt)

_file = logging.handlers.RotatingFileHandler(
    LOG_DIR / "yara-sigma.log",
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
_file.setFormatter(_fmt)

logging.basicConfig(level=logging.INFO, handlers=[_console, _file])
logger = logging.getLogger(__name__)

MAX_WORKERS = 4


def process_file(
    repo_root: Path,
    repo_name: str,
    repo_type: str,
    rel_path: str,
    seen_hashes: set,
    hash_lock: threading.Lock,
) -> dict[str, int]:
    """Parse a single source file and write one JSON per extracted rule."""
    stats: dict[str, int] = {"yara": 0, "sigma": 0}
    full_path = repo_root / rel_path

    if not full_path.exists():
        return stats

    kind = classify_file(rel_path, repo_type)
    if kind is None:
        return stats

    source_info = {
        "repo": repo_name,
        "file_path": rel_path.replace("\\", "/"),
        "filename": Path(rel_path).name,
    }

    if kind == "yara":
        rules = extract_yara_rules(full_path, source_info)
    else:
        rules = extract_sigma_rules(full_path, source_info)

    for rule in rules:
        raw_hash = hashlib.sha256(rule.get("raw", "").encode()).hexdigest()
        with hash_lock:
            if raw_hash in seen_hashes:
                logger.debug("Duplicate rule skipped: %s", rule.get("rule_name"))
                continue
            seen_hashes.add(raw_hash)

        normalized = normalize_rule(rule)
        if save_rule(normalized, repo_name, rel_path):
            stats[normalized["rule-type"]] += 1

    return stats


def process_repo(
    cfg: dict,
    state: dict,
    state_lock: threading.Lock,
    seen_hashes: set,
    hash_lock: threading.Lock,
):
    """Full pipeline for one repository: git sync -> parse -> write."""
    url = cfg["url"]
    rtype = cfg["type"]
    name = repo_name_from_url(url)
    dest = GITHUB_DIR / name

    try:
        repo, is_new = clone_or_pull(url, dest)
    except Exception as exc:
        logger.error("[%s] Clone/pull failed: %s", name, exc)
        return

    head = str(repo.head.commit)

    with state_lock:
        prev = state["repos"].get(name, {}).get("last_commit")

    if not is_new and prev == head:
        logger.info("[%s] Up-to-date — skipping.", name)
        return

    if is_new or prev is None:
        logger.info("[%s] Initial scan …", name)
        rule_files = scan_all_rule_files(dest, rtype)
        deleted: list[str] = []
    else:
        logger.info("[%s] Diff %s -> %s", name, prev[:8], head[:8])
        try:
            rule_files, deleted = changed_files_between(repo, prev, head)
        except Exception as exc:
            logger.warning("[%s] Diff failed (%s) — falling back to full scan", name, exc)
            rule_files = scan_all_rule_files(dest, rtype)
            deleted = []

    totals: dict[str, int] = {"yara": 0, "sigma": 0}
    processed_files = 0

    for rel in rule_files:
        st = process_file(dest, name, rtype, rel, seen_hashes, hash_lock)
        totals["yara"] += st["yara"]
        totals["sigma"] += st["sigma"]
        if st["yara"] or st["sigma"]:
            processed_files += 1

    for rel in deleted:
        remove_rules_for_file(name, rel)

    logger.info(
        "[%s] %d files -> %d YARA rules, %d Sigma rules",
        name,
        processed_files,
        totals["yara"],
        totals["sigma"],
    )

    with state_lock:
        state["repos"][name] = {
            "last_commit": head,
            "last_processed": datetime.now(timezone.utc).isoformat(),
        }
        save_state(state)


def main():
    GITHUB_DIR.mkdir(parents=True, exist_ok=True)

    state = load_state()

    if not state["repos"]:
        logger.info("Fresh state — clearing old output directory")
        if OUTPUT_DIR.exists():
            shutil.rmtree(OUTPUT_DIR)

    active_repos = {repo_name_from_url(cfg["url"]) for cfg in REPOS}
    for old_repo in list(state["repos"].keys()):
        if old_repo not in active_repos:
            logger.info("Repo removed from config — cleaning up: %s", old_repo)
            remove_repo_output(old_repo)
            del state["repos"][old_repo]
    save_state(state)

    (OUTPUT_DIR / "yara").mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "sigma").mkdir(parents=True, exist_ok=True)

    state_lock = threading.Lock()
    seen_hashes: set = set()
    hash_lock = threading.Lock()

    logger.info("Processing %d repos with %d parallel workers …", len(REPOS), MAX_WORKERS)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(process_repo, cfg, state, state_lock, seen_hashes, hash_lock): cfg
            for cfg in REPOS
        }
        for future in as_completed(futures):
            cfg = futures[future]
            try:
                future.result()
            except Exception as exc:
                logger.error("Unhandled error for %s: %s", cfg["url"], exc)

    print_summary(generate_summary())
    logger.info("All done.")


if __name__ == "__main__":
    main()
