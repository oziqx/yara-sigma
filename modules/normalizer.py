"""Rule normalizer — transforms raw rule dicts into Elasticsearch-ready documents."""


def _get_yara_metadata(parsed: dict) -> dict:
    """Flatten plyara's list-of-dicts metadata into a single dict."""
    meta = {}
    for item in parsed.get("metadata", []):
        if isinstance(item, dict):
            meta.update(item)
    return meta


def _to_tag_list(value) -> list[str]:
    """Convert any tag format to a flat list of strings."""
    if not value or value == "-":
        return []
    if isinstance(value, list):
        tags = [str(t).strip() for t in value if str(t).strip() and str(t).strip() != "-"]
    elif isinstance(value, str):
        tags = [t.strip() for t in value.replace(",", " ").split() if t.strip() and t.strip() != "-"]
    else:
        tags = [str(value).strip()]
    return tags if tags else []


def _str(value, default="-") -> str:
    if not value:
        return default
    s = str(value).strip()
    return s if s else default


def _normalize_yara(rule: dict) -> dict:
    parsed = rule.get("parsed", {})
    source = rule.get("source", {})
    meta = _get_yara_metadata(parsed)

    author = _str(
        meta.get("author") or meta.get("Author")
    )
    description = _str(
        meta.get("description") or meta.get("Description")
    )
    reference = _str(
        meta.get("reference") or meta.get("references") or meta.get("url")
    )
    threat_actor = _str(
        meta.get("threat_actor") or meta.get("actor") or meta.get("threat-actor")
    )

    raw_tags = parsed.get("tags", [])

    return {
        "id": rule["id"],
        "rule-name": rule["rule_name"],
        "rule-type": "yara",
        "rule-source": source.get("repo", "-"),
        "file-path": source.get("file_path", "-"),
        "rule": rule["raw"],
        "author": author,
        "description": description,
        "tags": _to_tag_list(raw_tags),
        "references": reference,
        "associated-threat-actor": _to_tag_list(threat_actor if threat_actor != "-" else None) or None,
        "timestamp": rule.get("extracted_at", "-"),
    }


def _normalize_sigma(rule: dict) -> dict:
    parsed = rule.get("parsed", {})
    source = rule.get("source", {})

    author = _str(parsed.get("author"))
    description = _str(parsed.get("description"))

    refs = parsed.get("references")
    if isinstance(refs, list):
        reference = ", ".join(str(r) for r in refs if r) or "-"
    else:
        reference = _str(refs)

    threat_actor = _str(
        parsed.get("threat_actor") or parsed.get("actor")
    )

    raw_tags = parsed.get("tags", [])

    return {
        "id": rule["id"],
        "rule-name": rule["rule_name"],
        "rule-type": "sigma",
        "rule-source": source.get("repo", "-"),
        "file-path": source.get("file_path", "-"),
        "rule": rule["raw"],
        "author": author,
        "description": description,
        "tags": _to_tag_list(raw_tags),
        "references": reference,
        "associated-threat-actor": _to_tag_list(threat_actor if threat_actor != "-" else None) or None,
        "timestamp": rule.get("extracted_at", "-"),
    }


def normalize_rule(rule: dict) -> dict:
    """Normalize a rule dict to Elasticsearch-ready format."""
    if rule.get("type") == "yara":
        return _normalize_yara(rule)
    if rule.get("type") == "sigma":
        return _normalize_sigma(rule)
    return rule
