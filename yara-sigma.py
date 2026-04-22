#!/usr/bin/env python3
"""
YARA & Sigma Rule Parser — Orchestrator

Clones/pulls GitHub repos, extracts individual YARA & Sigma rules,
validates them, and saves each rule as a separate JSON file.

Usage:
    python yara-sigma.py
"""

import logging
import shutil
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
from modules.output_writer import (
    generate_summary,
    print_summary,
    remove_rules_for_file,
    save_rule,
)
from parsers.sigma_parser import extract_sigma_rules
from parsers.yara_parser import extract_yara_rules
from modules.state_manager import load_state, save_state

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def process_file(
    repo_root: Path,
    repo_name: str,
    repo_type: str,
    rel_path: str,
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
        if save_rule(rule, repo_name, rel_path):
            stats[rule["type"]] += 1

    return stats


def process_repo(cfg: dict, state: dict):
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
        st = process_file(dest, name, rtype, rel)
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

    state["repos"][name] = {
        "last_commit": head,
        "last_processed": datetime.now(timezone.utc).isoformat(),
    }


def main():
    GITHUB_DIR.mkdir(parents=True, exist_ok=True)

    state = load_state()

    if not state["repos"]:
        logger.info("Fresh state — clearing old output directory")
        if OUTPUT_DIR.exists():
            shutil.rmtree(OUTPUT_DIR)

    (OUTPUT_DIR / "yara").mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "sigma").mkdir(parents=True, exist_ok=True)

    total = len(REPOS)
    for idx, cfg in enumerate(REPOS, 1):
        logger.info("--- [%d/%d] %s ---", idx, total, cfg["url"])
        process_repo(cfg, state)
        save_state(state)

    print_summary(generate_summary())
    logger.info("All done.")


if __name__ == "__main__":
    main()
