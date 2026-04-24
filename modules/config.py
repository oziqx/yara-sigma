"""Repository configuration for YARA & Sigma Rule Collector."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

GITHUB_DIR = BASE_DIR / "github"
OUTPUT_DIR = BASE_DIR / "output"
STATE_FILE = BASE_DIR / "state.json"

YARA_EXTENSIONS = {".yar", ".yara"}
SIGMA_EXTENSIONS = {".yml", ".yaml"}

IGNORE_DIRS = {
    ".git", ".github", ".circleci", ".gitlab",
    "node_modules", "__pycache__", ".venv", "venv",
    ".idea", ".vscode", "test", "tests", "example", "examples",
}

REPOS = [
    # ── YARA ────────────────────────────────────────────────────────
    {"url": "https://github.com/Neo23x0/signature-base.git",                "type": "yara"},
]
