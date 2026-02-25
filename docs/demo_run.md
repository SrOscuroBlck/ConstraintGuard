# Demo Run

This document describes how to run a complete ConstraintGuard demo locally.

## Prerequisites

- Python 3.10+
- Clang + scan-build on PATH (for full analyzer run)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Happy-path demo command

Run ConstraintGuard against the example vulnerable project with tight constraints:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/tight.yml \
  --out out/demo_tight
```

Or use the module entry point:

```bash
python -m constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/tight.yml \
  --out out/demo_tight
```

## Compare constraint profiles

Run with relaxed constraints and compare outputs:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/relaxed.yml \
  --out out/demo_relaxed
```

Differences should be visible in severity distribution, finding ordering, and rule traces.

## Generate a sample report from mocked data

To verify models and JSON serialization without running the analyzer:

```bash
python examples/mock_pipeline.py
```

This produces `examples/sample_report.json` with a fully populated report structure.

## CLI help

```bash
constraintguard --help
constraintguard run --help
constraintguard score --help
```
