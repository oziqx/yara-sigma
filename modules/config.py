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
    {"url": "https://github.com/Neo23x0/signature-base.git",                "type": "yara"},
    {"url": "https://github.com/Yara-Rules/rules.git",                      "type": "yara"},
    {"url": "https://github.com/reversinglabs/reversinglabs-yara-rules.git", "type": "yara"},
    {"url": "https://github.com/elastic/protections-artifacts.git",          "type": "yara"},
    {"url": "https://github.com/malpedia/signator-rules.git",               "type": "yara"},
    {"url": "https://github.com/bartblaze/Yara-rules.git",                  "type": "yara"},
    {"url": "https://github.com/ditekshen/detection.git",                   "type": "both"},
    {"url": "https://github.com/volexity/threat-intel.git",                 "type": "yara"},
    {"url": "https://github.com/mandiant/red_team_tool_countermeasures.git", "type": "yara"},
    {"url": "https://github.com/RussianPanda95/Yara-Rules.git",             "type": "yara"},
    {"url": "https://github.com/intezer/yara-rules.git",                    "type": "yara"},
    {"url": "https://github.com/chronicle/GCTI.git",                        "type": "yara"},
    {"url": "https://github.com/delivr-to/detections.git",                  "type": "yara"},
    {"url": "https://github.com/jeFF0Falltrades/YARA-Signatures.git",       "type": "yara"},
    {"url": "https://github.com/StrangerealIntel/DailyIOC.git",             "type": "yara"},
    {"url": "https://github.com/telekom-security/malware_analysis.git",     "type": "yara"},
    {"url": "https://github.com/eset/malware-ioc.git",                      "type": "yara"},
    {"url": "https://github.com/anyrun/YARA.git",                           "type": "yara"},
    {"url": "https://github.com/advanced-threat-research/Yara-Rules.git",   "type": "yara"},

    # ── Sigma ───────────────────────────────────────────────────────
    {"url": "https://github.com/SigmaHQ/sigma.git",                         "type": "sigma"},
    {"url": "https://github.com/mdecrevoisier/SIGMA-detection-rules.git",   "type": "sigma"},

    # ── Both (YARA + Sigma) ─────────────────────────────────────────
    {"url": "https://github.com/rapid7/Rapid7-Labs.git", "type": "both"},

]
