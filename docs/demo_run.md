# Demo Run

This document describes how to run a complete ConstraintGuard demo locally.

## Prerequisites

- Python 3.10+
- Clang + scan-build on PATH (required only for the full analyzer pipeline)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Constraint comparison demo (works today, no scan-build required)

This is the primary entry point for demonstrating the research contribution. The script
scores the same 8 findings under both `tight.yml` and `relaxed.yml` using the real
deterministic scoring engine and prints a side-by-side tier comparison.

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

Expected output: builds `examples/vuln_demo/vuln_demo` binary with one warning about
the intentional uninitialized-value pattern in `compute_checksum`.

---

## Full pipeline run (requires scan-build)

When the end-to-end CLI pipeline is fully wired, the comparison can be run using real
Clang Static Analyzer output. These commands are documented here as the intended
production workflow:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/tight.yml \
  --out out/demo_tight
```

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/relaxed.yml \
  --out out/demo_relaxed
```

Differences will be visible in severity distribution, finding ordering, and rule traces
across `out/demo_tight/report.md` and `out/demo_relaxed/report.md`.

---

## Generate a sample JSON report from mocked data

Verifies model serialization and the console reporting layer without requiring scan-build:

```bash
python examples/mock_pipeline.py
```

Produces `examples/sample_report.json`.

---

## CLI help

```bash
constraintguard --help
constraintguard run --help
constraintguard score --help
```
