# Getting Started

This guide targets the **Phase 1 Demo**: run ConstraintGuard locally, end-to-end, on a small example project and produce a ranked report.

## Prerequisites

- Python 3.10+
- Clang tooling with `scan-build` available (recommended for the demo runner)
- A C/C++ build environment for your target sample project (make/cmake/ninja)

If you cannot install `scan-build`, you can still run the pipeline by providing a pre-generated SARIF file.

## Install (local dev)

From the repository root (example):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Minimal demo flow

You will run ConstraintGuard with:
- a repository path (`--source`),
- a constraint config (`--config`),
- a build command (`--build-cmd`),
- an output directory (`--out`).

Example:

```bash
constraintguard \
  --source examples/demo_project \
  --config examples/demo_project/.constraintguard.yml \
  --build-cmd "make clean && make" \
  --out out/demo_run
```

Expected outputs inside `out/demo_run/`:
- `constraints.json` (normalized `HardwareSpec` + provenance)
- `findings.sarif` (or a folder containing SARIF outputs)
- `report.json` (full results)
- `report.md` (human-readable ranking)

## Demonstrating constraint sensitivity (key demo)
A core demo requirement is that the **same code** produces different prioritization when constraints change.

Run with a “tight” profile:

```bash
constraintguard --source examples/demo_project \
  --config examples/demo_project/config_tight.yml \
  --build-cmd "make clean && make" \
  --out out/tight
```

Run with a “relaxed” profile:

```bash
constraintguard --source examples/demo_project \
  --config examples/demo_project/config_relaxed.yml \
  --build-cmd "make clean && make" \
  --out out/relaxed
```

Compare:
- severity distribution
- top-5 ranking
- rule traces for findings that changed tiers

## Configuration file (.constraintguard.yml)

The YAML is intended to capture both quantitative constraints and explicit intent.
A minimal example:

```yaml
platform: cortex-m-demo
ram_size: 20KB
flash_size: 256KB
stack_size: 2KB
heap_size: 4KB
max_interrupt_latency: 50us
critical_functions:
  - handle_interrupt
  - safety_shutdown
safety_level: ISO26262-ASILB
```

Notes:
- sizes and times are normalized (KB/MB/us/ms supported)
- missing fields must be treated explicitly (default/unknown), never silently assumed

## Troubleshooting

### No SARIF produced
- Ensure `scan-build` is installed and in PATH.
- Try running `scan-build --help` to confirm availability.
- Confirm your build command succeeds without `scan-build` first.

### Too many findings / noisy results
- The demo phase does not optimize analyzer configuration yet.
- You can add a filter option later (ruleId allow/deny) to reduce noise.

### Constraint parsing fails
- Start with YAML-only constraints for the demo.
- Add linker-script parsing gradually once the YAML path is stable.
