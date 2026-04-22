# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

A Python automation tool that clones GitHub repositories containing YARA and Sigma threat-detection rules, extracts individual rules from potentially dirty files, validates them, and saves each rule as a separate JSON file. It tracks repository state between runs to perform incremental updates via git diff.

## Running the Tool

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full pipeline
python yara-sigma.py
```

There are no tests or linting configurations in this project.

## Architecture

```
yara-sigma.py           # Orchestrator: drives the per-repo pipeline
modules/
  config.py             # Paths (GITHUB_DIR, OUTPUT_DIR, STATE_FILE) and REPOS list
  git_manager.py        # clone_or_pull, changed_files_between, scan_all_rule_files, classify_file
  state_manager.py      # JSON state file tracking last commit hash per repo (state.json)
  output_writer.py      # save_rule, remove_rules_for_file, generate_summary
parsers/
  yara_parser.py        # extract_yara_rules — plyara + yara-python compile check
  sigma_parser.py       # extract_sigma_rules — PyYAML + optional pySigma validation
```

**Runtime directories** (created on first run, not in source):
- `github/` — cloned repositories, named `{owner}_{repo}`
- `output/yara/` and `output/sigma/` — one JSON per extracted rule
- `state.json` — last-processed commit hash per repo

## Key Design Decisions

**Incremental processing**: On subsequent runs, `git_manager.changed_files_between` diffs `prev_commit..HEAD` so only modified/added/deleted files are re-processed. Falls back to full scan if the diff fails.

**State versioning**: `state_manager.CURRENT_FORMAT_VERSION = 2`. Bumping this integer forces a full re-scan of all repos and clears the output directory on the next run.

**Output layout**: `output/{yara|sigma}/{repo_name}/{rel_dir}/{source_filename}/{rule_name}.json`. This preserves full provenance (repo → folder → file → rule).

**Dirty-file tolerance**: YARA parser tries plyara on the whole file first; falls back to regex extraction (`YARA_RULE_RE`) per rule block if plyara fails. Sigma parser tries `yaml.safe_load_all` then splits on `\n---` as a fallback.

**Optional dependencies**: `yara-python` and `pySigma` degrade gracefully — compile validation is skipped when missing; pySigma failures are logged as debug but don't drop rules.

## Adding or Removing Repositories

Edit the `REPOS` list in `modules/config.py`. Each entry is `{"url": "<git-url>", "type": "yara"|"sigma"|"both"}`. The `"both"` type scans `.yar`/`.yara` files as YARA and `.yml`/`.yaml` files as Sigma within the same repo.

## File Classification

`classify_file` in `git_manager.py` maps extensions to rule type based on repo type. Directories listed in `IGNORE_DIRS` (`.git`, `tests`, `examples`, etc.) are pruned during walk.
