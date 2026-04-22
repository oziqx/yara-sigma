"""Output writer — saves each parsed rule as a JSON file.

Directory layout:
    output/{yara|sigma}/{repo}/{rel_dir}/{source_filename}/{rule_name}.json

This preserves the full provenance chain (repo -> folder -> file -> rule).
"""

import json
import logging
import re
import shutil
from pathlib import Path

from .config import OUTPUT_DIR

logger = logging.getLogger(__name__)


def _sanitize(name: str) -> str:
    """Make a string safe for use as a filesystem name."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = name.strip(". ")
    if not name:
        name = "_unnamed"
    return name[:200]


def save_rule(rule: dict, repo_name: str, rel_file_path: str) -> Path | None:
    """Write a single rule dict to the correct output location.

    Returns the path written, or None on failure.
    """
    kind = rule.get("rule-type") or rule.get("type", "unknown")
    rule_name = rule.get("rule-name") or rule.get("rule_name", "unknown")

    rel = Path(rel_file_path)
    dst = (
        OUTPUT_DIR
        / kind
        / repo_name
        / rel.parent
        / rel.name
        / f"{_sanitize(rule_name)}.json"
    )
    dst.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(dst, "w", encoding="utf-8") as fh:
            json.dump(rule, fh, indent=2, ensure_ascii=False, default=str)
        return dst
    except Exception as exc:
        logger.warning("Failed to write %s: %s", dst, exc)
        return None


def remove_repo_output(repo_name: str):
    """Remove all output JSONs for a repo that no longer exists in REPOS."""
    for kind in ("yara", "sigma"):
        target = OUTPUT_DIR / kind / repo_name
        if target.exists() and target.is_dir():
            shutil.rmtree(target)
            logger.info("Removed output for deleted repo: %s", repo_name)


def remove_rules_for_file(repo_name: str, rel_file_path: str):
    """Remove all output JSONs derived from a given source file."""
    rel = Path(rel_file_path)
    for kind in ("yara", "sigma"):
        target = OUTPUT_DIR / kind / repo_name / rel.parent / rel.name
        if target.exists() and target.is_dir():
            shutil.rmtree(target)
            logger.debug("Removed output dir: %s", target)


def generate_summary() -> dict[str, dict[str, int]]:
    """Count JSON rule files per repo, grouped by type."""
    summary: dict[str, dict[str, int]] = {}
    for kind in ("yara", "sigma"):
        kind_dir = OUTPUT_DIR / kind
        if not kind_dir.exists():
            continue
        for repo_dir in sorted(kind_dir.iterdir()):
            if not repo_dir.is_dir():
                continue
            count = sum(1 for f in repo_dir.rglob("*.json") if f.is_file())
            if count:
                summary.setdefault(kind, {})[repo_dir.name] = count
    return summary


def print_summary(summary: dict[str, dict[str, int]]):
    logger.info("=" * 60)
    logger.info("  COLLECTION SUMMARY  (individual rules)")
    logger.info("=" * 60)
    for kind in ("yara", "sigma"):
        repos = summary.get(kind, {})
        total = sum(repos.values())
        logger.info("  %s rules total: %d", kind.upper(), total)
        for rname, cnt in sorted(repos.items(), key=lambda x: -x[1]):
            logger.info("    %-45s %5d", rname, cnt)
        logger.info("-" * 60)
