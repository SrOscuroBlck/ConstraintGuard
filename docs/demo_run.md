# Demo Run

This document describes how to run a complete ConstraintGuard demo locally.

## Prerequisites

- Python 3.10+
- Clang + scan-build on PATH (required only for the `run` subcommand)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Quick start: score a SARIF file (no scan-build required)

The `score` subcommand parses an existing SARIF file, loads constraints from a YAML
config (and optionally a linker script), runs the deterministic scoring engine, and
produces console output + JSON + Markdown reports.

```bash
constraintguard score \
  --sarif examples/vuln_demo/findings.sarif \
  --config examples/configs/tight.yml \
  --out out/demo_tight
```

Compare with a relaxed constraint profile on the same SARIF:

```bash
constraintguard score \
  --sarif examples/vuln_demo/findings.sarif \
  --config examples/configs/relaxed.yml \
  --out out/demo_relaxed
```

Inspect the outputs:

```bash
cat out/demo_tight/report.md
cat out/demo_relaxed/report.md
```

### Expected difference

Under tight constraints (cortex-m4, 2KB stack, 50µs latency, ISO26262-ASIL-B):
- **5 CRITICAL**, 2 HIGH, 1 MEDIUM

Under relaxed constraints (cortex-a53, 8MB stack, 1ms latency, IEC62443-SL1):
- **1 CRITICAL**, 1 HIGH, 6 MEDIUM

6 of 8 findings change severity tier — identical SARIF input, constraint-aware
prioritization drives the difference.

---

## Constraint comparison demo (side-by-side output)

For a compact side-by-side view showing both profiles at once:

```bash
python examples/demo_comparison.py
```

### Expected output (abbreviated)

```
════════════════════════════════════════════════════════════════════════
  ConstraintGuard — Constraint Comparison Demo
  Same code, same findings, different constraint profiles → different risk tiers
════════════════════════════════════════════════════════════════════════

  Constraint Profiles
  ────────────────────────────────────────────────────────────────────────
  tight  (tight.yml)
    platform=cortex-m4  stack=2048B  heap=4096B  ram=20480B
    latency=50µs  safety=ISO26262-ASIL-B
    critical_functions=[control_loop, isr_uart, watchdog_feed]

  relaxed (relaxed.yml)
    platform=cortex-a53  stack=8388608B  heap=67108864B  ram=536870912B
    latency=1000µs  safety=IEC62443-SL1
    critical_functions=[auth_handler]

  Severity Distribution
  ────────────────────────────────────────────────────────────────────────
  tight
    CRITICAL  █████  5
    HIGH      ██░░░  2
    MEDIUM    █░░░░  1

  relaxed
    CRITICAL  █░░░░░  1
    HIGH      █░░░░░  1
    MEDIUM    ██████  6

  Per-Finding Comparison  (← TIER CHANGED marks constraint-driven re-rankings)
  ────────────────────────────────────────────────────────────────────────

  [1] buffer_overflow  [security.insecureAPI.strcpy]
      examples/vuln_demo/main.c:15  in copy_input
      Tight:   CRITICAL  score=100  rules: R-MEM-STACK-TIGHT(+20), R-MEM-RAM-TIGHT(+15), ...
      Relaxed: MEDIUM    score= 65  rules: R-SAFETY-FUNCTIONAL(+5)  ← TIER CHANGED

  [7] buffer_overflow  [security.insecureAPI.strcpy]
      examples/vuln_demo/main.c:76  in isr_uart
      Tight:   CRITICAL  score=100  rules: R-MEM-STACK-TIGHT(+20), R-ISR-FUNC-NAME(+25), R-CRIT-FUNC(+25), ...
      Relaxed: CRITICAL  score= 90  rules: R-ISR-FUNC-NAME(+25), R-SAFETY-FUNCTIONAL(+5)

  [8] null_deref  [core.NullDereference]
      examples/vuln_demo/main.c:83  in control_loop
      Tight:   CRITICAL  score=100  rules: R-MEM-RAM-TIGHT(+15), R-CRIT-FUNC(+25), ...
      Relaxed: MEDIUM    score= 55  rules: R-SAFETY-FUNCTIONAL(+5)  ← TIER CHANGED

════════════════════════════════════════════════════════════════════════
  6 of 8 findings changed severity tier between tight and relaxed profiles.
  Identical SARIF input — constraint-aware prioritization drives the difference.
════════════════════════════════════════════════════════════════════════
```

### Key observations

- Finding [7] (`isr_uart`) remains CRITICAL under both profiles but for different reasons:
  tight fires 8 rules including stack/RAM/latency/ASIL constraints; relaxed fires only 2
  (ISR naming is intrinsically critical regardless of resource targets).
- Finding [6] (`compute_checksum`) stays MEDIUM under both but the score drops from 55 to 45
  because the ultra-tight latency rule (`R-TIME-ULTRA-TIGHT`) no longer applies.
- Finding [4] (`process_buffer`, use-after-free) moves from CRITICAL to HIGH — not MEDIUM —
  because use-after-free has a higher base score (65) that keeps it relevant even without
  constraint escalation.

---

## Build the vulnerable example project

Verifies that the C project compiles cleanly (warnings from intentional patterns are expected):

```bash
make -C examples/vuln_demo
```

---

## Full pipeline run (requires scan-build)

The `run` subcommand executes `scan-build` on your project, captures SARIF output, scores
all findings, and generates reports in a single command:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/tight.yml \
  --out out/demo_tight
```

Compare with a relaxed profile:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/relaxed.yml \
  --out out/demo_relaxed
```

---

## Score your own project

If you already have SARIF output from any analyzer:

```bash
constraintguard score \
  --sarif /path/to/results.sarif \
  --config /path/to/.constraintguard.yml \
  --out out/my_project
```

You can also merge constraints from a linker script:

```bash
constraintguard score \
  --sarif /path/to/results.sarif \
  --config /path/to/.constraintguard.yml \
  --linker-script /path/to/linker.ld \
  --out out/my_project
```

---

## Output files

Each run produces deterministic output in the `--out` directory:

- `report.json` — full structured report (constraints, findings, scores, rule traces)
- `report.md` — human-friendly Markdown summary

---

## CLI help

```bash
constraintguard --help
constraintguard run --help
constraintguard score --help
```
