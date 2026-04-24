"""Elasticsearch writer — indexes parsed rules into ES.

Reads connection config from environment variables (loaded via .env).
Call `connect()` once at startup, then `bulk_index_rules()` per repo.
"""

import hashlib
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logger = logging.getLogger(__name__)

_client = None

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "rule-type":      {"type": "keyword"},
            "rule-name":      {"type": "keyword"},
            "rule-id":        {"type": "keyword"},
            "description":    {"type": "text"},
            "author":         {"type": "keyword"},
            "tags":           {"type": "keyword"},
            "severity":       {"type": "keyword"},
            "status":         {"type": "keyword"},
            "repo":           {"type": "keyword"},
            "file_path":      {"type": "keyword"},
            "filename":       {"type": "keyword"},
            "raw":            {"type": "text", "index": False},
            "ingested_at":    {"type": "date"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}


def connect() -> bool:
    """Initialize the ES client from env vars. Returns True on success."""
    global _client
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        logger.error("elasticsearch package not installed — run: pip install elasticsearch")
        return False

    host = os.getenv("ES_HOST", "http://localhost")
    port = os.getenv("ES_PORT", "9200")
    username = os.getenv("ES_USERNAME", "")
    password = os.getenv("ES_PASSWORD", "")
    api_key = os.getenv("ES_API_KEY", "")

    url = f"{host}:{port}"

    kwargs: dict = {"hosts": [url], "request_timeout": 30}

    if api_key:
        kwargs["api_key"] = api_key
    elif username and password:
        kwargs["basic_auth"] = (username, password)

    try:
        _client = Elasticsearch(**kwargs)
        info = _client.info()
        version = info["version"]["number"]
        cluster = info["cluster_name"]
        logger.info("Elasticsearch connected — cluster: %s  version: %s", cluster, version)
        return True
    except Exception as exc:
        logger.error("Elasticsearch connection failed: %s", exc)
        _client = None
        return False


def ensure_index() -> bool:
    """Create the index with mapping if it does not already exist."""
    if _client is None:
        return False
    index = os.getenv("ES_INDEX", "threat-detection-rules")
    try:
        if not _client.indices.exists(index=index):
            _client.indices.create(index=index, body=INDEX_MAPPING)
            logger.info("Created ES index: %s", index)
        else:
            logger.debug("ES index already exists: %s", index)
        return True
    except Exception as exc:
        logger.error("Failed to ensure ES index: %s", exc)
        return False


def _rule_id(rule: dict) -> str:
    """Stable document ID: sha256 of raw content, or rule-name+repo fallback."""
    raw = rule.get("raw", "")
    if raw:
        return hashlib.sha256(raw.encode()).hexdigest()
    key = f"{rule.get('repo','')}/{rule.get('rule-name','unknown')}"
    return hashlib.sha256(key.encode()).hexdigest()


def bulk_index_rules(rules: list[dict]) -> int:
    """Bulk upsert a list of rule dicts. Returns number of indexed docs."""
    if _client is None or not rules:
        return 0

    from elasticsearch.helpers import bulk

    index = os.getenv("ES_INDEX", "threat-detection-rules")
    actions = [
        {
            "_index": index,
            "_id": _rule_id(rule),
            "_source": rule,
        }
        for rule in rules
    ]

    try:
        ok, errors = bulk(_client, actions, raise_on_error=False, stats_only=False)
        if errors:
            logger.warning("%d bulk index errors (first: %s)", len(errors), errors[0])
        logger.debug("Bulk indexed %d rules to %s", ok, index)
        return ok
    except Exception as exc:
        logger.error("Bulk index failed: %s", exc)
        return 0


def bulk_delete_by_file(repo_name: str, rel_file_path: str) -> int:
    """Delete all rules that came from a specific source file."""
    if _client is None:
        return 0
    index = os.getenv("ES_INDEX", "threat-detection-rules")
    try:
        resp = _client.delete_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"repo": repo_name}},
                            {"term": {"file_path": rel_file_path.replace("\\", "/")}},
                        ]
                    }
                }
            },
            refresh=True,
        )
        deleted = resp.get("deleted", 0)
        if deleted:
            logger.debug("Deleted %d ES docs for %s/%s", deleted, repo_name, rel_file_path)
        return deleted
    except Exception as exc:
        logger.error("bulk_delete_by_file failed: %s", exc)
        return 0
