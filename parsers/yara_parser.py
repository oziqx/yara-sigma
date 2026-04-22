"""YARA rule extraction and validation pipeline.

Pipeline:
  1. Pre-filter: skip files that don't contain 'rule ' and '{'
  2. Parse with plyara (whole-file first, regex fallback for dirty files)
  3. Validate each rule with yara.compile
  4. Return list of enriched rule dicts ready for JSON output
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)
logging.getLogger("plyara").setLevel(logging.WARNING)

try:
    import yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not installed — compile validation disabled")

try:
    from plyara import Plyara
    from plyara.utils import rebuild_yara_rule

    HAS_PLYARA = True
except ImportError:
    HAS_PLYARA = False
    logger.warning("plyara not installed — YARA parsing disabled")


IMPORT_RE = re.compile(r'^\s*import\s+"[^"]+"\s*$', re.MULTILINE)

YARA_RULE_RE = re.compile(
    r"(?:(?:private|global)\s+)*"
    r"rule\s+\w+"
    r"(?:\s*:\s*[^\{]+)?"
    r"\s*\{"
    r".*?"
    r"\n\}",
    re.DOTALL,
)


def _extract_imports(content: str) -> str:
    """Pull all ``import "..."`` lines so we can prepend them during compile."""
    imports = IMPORT_RE.findall(content)
    return "\n".join(imports) + "\n" if imports else ""


def _compile_check(source: str) -> bool:
    if not HAS_YARA:
        return True
    try:
        yara.compile(source=source)
        return True
    except Exception:
        return False


def _parse_with_plyara(content: str) -> list[dict] | None:
    """Try to parse the full file content. Returns None on failure."""
    try:
        parser = Plyara()
        return parser.parse_string(content)
    except Exception:
        return None


def _parse_with_regex(content: str) -> list[dict]:
    """Fallback: regex-extract rule blocks, then parse each individually."""
    results: list[dict] = []
    for match in YARA_RULE_RE.finditer(content):
        try:
            p = Plyara()
            block_rules = p.parse_string(match.group(0))
            results.extend(block_rules)
        except Exception:
            continue
    return results


def _make_serializable(obj):
    """Ensure every value in the plyara dict is JSON-safe."""
    if isinstance(obj, dict):
        return {str(k): _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_serializable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def extract_yara_rules(file_path: Path, source_info: dict) -> list[dict]:
    """Extract, validate and parse every YARA rule from *file_path*.

    Returns a list of rule dicts, each containing:
      type, rule_name, source, raw, parsed, extracted_at
    """
    if not HAS_PLYARA:
        return []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    if "rule " not in content or "{" not in content:
        return []

    import_block = _extract_imports(content)

    parsed_rules = _parse_with_plyara(content)
    if parsed_rules is None:
        parsed_rules = _parse_with_regex(content)

    if not parsed_rules:
        return []

    all_valid = _compile_check(content)

    now = datetime.now(timezone.utc).isoformat()
    results: list[dict] = []

    for rule in parsed_rules:
        rule_name = rule.get("rule_name", "unknown")

        try:
            raw = rebuild_yara_rule(rule)
        except Exception:
            continue

        if not all_valid:
            if not _compile_check(import_block + raw) and not _compile_check(raw):
                logger.debug("Skipping invalid YARA rule: %s", rule_name)
                continue

        results.append(
            {
                "id": hashlib.sha256(raw.encode()).hexdigest(),
                "type": "yara",
                "rule_name": rule_name,
                "source": source_info,
                "raw": raw,
                "parsed": _make_serializable(rule),
                "extracted_at": now,
            }
        )

    return results
