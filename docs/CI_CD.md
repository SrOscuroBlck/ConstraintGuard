# CI/CD Integration

ConstraintGuard ships as a reusable GitHub Action that can be added to any C/C++
project. On every PR, it scores static analysis findings against your hardware
constraints and posts a summary comment showing severity distribution, top findings,
and which constraint-driven rules fired.

## Quick start

### 1. Add a constraint config to your repo

Create `.constraintguard.yml` in your repository root:

```yaml
platform: "cortex-m4"
ram_size: "20KB"
flash_size: "256KB"
stack_size: "2KB"
heap_size: "4KB"
max_interrupt_latency: "50us"

safety_level: "ISO26262-ASIL-B"
critical_functions:
  - "control_loop"
  - "isr_uart"
  - "watchdog_feed"
```

### 2. Add the workflow

Create `.github/workflows/constraintguard.yml`:

```yaml
name: ConstraintGuard

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  constraintguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: your-org/ConstraintGuard@main
        with:
          mode: score
          sarif-path: "path/to/results.sarif"
          config-path: ".constraintguard.yml"
          fail-on: "critical"
```

Replace `your-org/ConstraintGuard@main` with the actual path to this repository.

### 3. Push a PR

The action will:
1. Install ConstraintGuard
2. Score all SARIF findings against your constraint profile
3. Post a PR comment with severity distribution + top findings
4. Upload the full report as a workflow artifact
5. Fail the check if any finding reaches the `--fail-on` threshold

---

## Modes

### Score existing SARIF (recommended)

Works with SARIF output from any analyzer — Clang SA, CodeQL, Semgrep, Coverity, etc.

```yaml
- uses: your-org/ConstraintGuard@main
  with:
    mode: score
    sarif-path: "results.sarif"
    config-path: ".constraintguard.yml"
```

You can pass multiple SARIF files (space-separated):

```yaml
sarif-path: "scan1.sarif scan2.sarif"
```

### Run scan-build + score

Runs Clang Static Analyzer via `scan-build`, captures SARIF, and scores — all in one step.

```yaml
- uses: your-org/ConstraintGuard@main
  with:
    mode: run
    source-path: "."
    build-cmd: "make"
    config-path: ".constraintguard.yml"
```

Requires Clang/LLVM installed on the runner. Add this before the action step:

```yaml
- run: |
    sudo apt-get update -qq
    sudo apt-get install -y clang clang-tools
```

### Use with CodeQL

If your project already uses GitHub's CodeQL analysis, you can export the SARIF and
feed it to ConstraintGuard:

```yaml
jobs:
  codeql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: github/codeql-action/init@v3
        with:
          languages: cpp

      - run: make

      - uses: github/codeql-action/analyze@v3
        with:
          output: codeql-results

      - uses: your-org/ConstraintGuard@main
        with:
          mode: score
          sarif-path: "codeql-results/cpp.sarif"
          config-path: ".constraintguard.yml"
          fail-on: "high"
```

---

## Action inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `mode` | No | `score` | `score` (parse SARIF) or `run` (scan-build + score) |
| `sarif-path` | When mode=score | — | Path(s) to SARIF file(s), space-separated |
| `config-path` | Yes | — | Path to `.constraintguard.yml` |
| `linker-script` | No | — | Path to linker script (`.ld`) for memory extraction |
| `source-path` | When mode=run | `.` | Source directory for scan-build |
| `build-cmd` | When mode=run | — | Build command (e.g. `make`) |
| `fail-on` | No | — | Fail if any finding ≥ this tier: `critical`, `high`, `medium`, `low` |
| `top-k` | No | `5` | Top N findings to show in the PR comment |
| `comment-on-pr` | No | `true` | Post a summary comment on the PR |

## Action outputs

| Output | Description |
|--------|-------------|
| `report-json` | Path to `report.json` |
| `report-md` | Path to `report.md` |
| `exit-code` | `0` = pass, `2` = threshold exceeded |
| `total-findings` | Total finding count |
| `critical-count` | Number of CRITICAL findings |
| `high-count` | Number of HIGH findings |

---

## PR comment format

The PR comment includes:

1. **Status indicator** — pass/fail based on `--fail-on` threshold
2. **Target summary** — platform and safety standard
3. **Severity distribution table** with visual bars
4. **Top N findings** — tier, score, category, location, function, and fired rules
5. **Link to full report** — uploaded as a workflow artifact

The comment is updated in-place on subsequent pushes (no duplicate comments).

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All findings are below the `--fail-on` threshold (or no threshold set) |
| `1` | Runtime error (bad config, missing files, etc.) |
| `2` | Policy violation — at least one finding meets or exceeds the threshold |

---

## Example: fail on CRITICAL in tight-constraint embedded projects

```yaml
- uses: your-org/ConstraintGuard@main
  with:
    mode: score
    sarif-path: "build/analysis.sarif"
    config-path: ".constraintguard.yml"
    fail-on: "critical"
    top-k: "10"
```

Under tight constraints (cortex-m4, 2KB stack, ISO 26262 ASIL-B), a buffer overflow
in `control_loop` scores 100 and triggers CRITICAL. Under relaxed constraints
(cortex-a53, 8MB stack), the same finding scores 65 (MEDIUM). The constraint profile
determines which findings block the PR.
