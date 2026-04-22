"""State management — tracks last-processed commit per repo with format versioning."""

import json
import logging
from pathlib import Path

from .config import STATE_FILE

logger = logging.getLogger(__name__)

CURRENT_FORMAT_VERSION = 2


def load_state() -> dict:
    """Load state from disk.

    Returns an empty repos dict when the file is missing or the format
    version has changed, which forces a full re-scan of every repo.
    """
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            if state.get("format_version") == CURRENT_FORMAT_VERSION:
                return state
            logger.info("State format version changed — all repos will be re-processed")
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupt state file (%s) — starting fresh", exc)

    return {"repos": {}, "format_version": CURRENT_FORMAT_VERSION}


def save_state(state: dict):
    state["format_version"] = CURRENT_FORMAT_VERSION
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
