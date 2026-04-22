"""Sigma rule extraction and validation pipeline.

Pipeline:
  1. Pre-filter: skip files without 'detection:' keyword
  2. Split multi-document YAML (--- separator) and load each block
  3. Validate required keys (detection, optionally logsource/title)
  4. Optional deep validation with pySigma if installed
  5. Return list of enriched rule dicts ready for JSON output
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

try:
    from sigma.rule import SigmaRule

    HAS_PYSIGMA = True
except ImportError:
    HAS_PYSIGMA = False


def _is_sigma_dict(doc: dict) -> bool:
    return isinstance(doc, dict) and "detection" in doc


def _make_serializable(obj):
    """Ensure every value is JSON-safe (dates, custom objects, etc.)."""
    if isinstance(obj, dict):
        return {str(k): _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_serializable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def _load_documents(content: str) -> list[dict]:
    """Parse YAML, handling multi-document files and dirty content."""
    try:
        docs = list(yaml.safe_load_all(content))
        return [d for d in docs if isinstance(d, dict)]
    except yaml.YAMLError:
        pass

    results: list[dict] = []
    for block in content.split("\n---"):
        block = block.strip()
        if not block:
            continue
        try:
            doc = yaml.safe_load(block)
            if isinstance(doc, dict):
                results.append(doc)
        except yaml.YAMLError:
            continue
    return results


def _validate_with_pysigma(raw_yaml: str) -> bool:
    if not HAS_PYSIGMA:
        return True
    try:
        SigmaRule.from_yaml(raw_yaml)
        return True
    except Exception:
        return False


def extract_sigma_rules(file_path: Path, source_info: dict) -> list[dict]:
    """Extract and validate every Sigma rule from *file_path*.

    Returns a list of rule dicts, each containing:
      type, rule_name, source, raw, parsed, extracted_at
    """
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    if "detection:" not in content:
        return []

    documents = _load_documents(content)
    if not documents:
        return []

    now = datetime.now(timezone.utc).isoformat()
    results: list[dict] = []

    for doc in documents:
        if not _is_sigma_dict(doc):
            continue

        title = str(doc.get("title", "untitled"))

        try:
            raw = yaml.dump(doc, default_flow_style=False, allow_unicode=True)
        except Exception:
            continue

        if HAS_PYSIGMA and not _validate_with_pysigma(raw):
            logger.debug("pySigma validation failed for: %s", title)
            continue

        results.append(
            {
                "type": "sigma",
                "rule_name": title,
                "source": source_info,
                "raw": raw,
                "parsed": _make_serializable(doc),
                "extracted_at": now,
            }
        )

    return results
