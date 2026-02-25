# Getting Started (Local Manual Run)

This guide helps you run ConstraintGuard locally to analyze an embedded C/C++ project and produce a ranked report.

> ConstraintGuard’s core pipeline is deterministic and does not require any AI services.

## Prerequisites

- Python 3.10+ (recommended 3.11)
- Clang + scan-build available on PATH
- A C/C++ project that can be built locally
- (Optional) a `.constraintguard.yml` file for constraints and safety context
- (Optional) a linker script `.ld` file if you want auto-extraction of RAM/FLASH/stack/heap

## Installation (development mode)

1. Create and activate a virtual environment.
2. Install dependencies.

Example:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

If the repository includes a `requirements.txt`, you may also run:

```bash
pip install -r requirements.txt
```

## Quick demo using the provided example

From the repo root:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/tight.yml \
  --out out/demo_tight
```

Then compare with a relaxed constraint profile:

```bash
constraintguard run \
  --source examples/vuln_demo \
  --build-cmd "make -C examples/vuln_demo" \
  --config examples/configs/relaxed.yml \
  --out out/demo_relaxed
```

You should see differences in:
- severity distribution,
- top findings ordering,
- rule traces (constraints that caused escalation/demotion).

## Running on your own project

Minimal run (with YAML constraints):

```bash
constraintguard run \
  --source /path/to/your/project \
  --build-cmd "cmake --build build" \
  --config /path/to/.constraintguard.yml \
  --out out/your_project
```

If you already have SARIF:

```bash
constraintguard score \
  --sarif /path/to/results.sarif \
  --config /path/to/.constraintguard.yml \
  --out out/your_project
```

## Outputs

In the output directory you will typically find:

- `report.json` – machine-readable full report
- `report.md` – human-friendly Markdown summary
- `run.log` – optional run log including constraint provenance
- `sarif/` – collected SARIF files (if generated)

## Troubleshooting

### scan-build not found
Install LLVM/Clang and ensure `scan-build` is on PATH.

### Build command fails
ConstraintGuard does not fix build systems. Verify you can build the project without ConstraintGuard first, then pass the same command via `--build-cmd`.

### No findings produced
Some projects may yield few findings depending on analyzer settings and code maturity. Use the provided example to validate your installation and pipeline first.

### Constraints missing or ambiguous
ConstraintGuard will log which constraints were derived and which were “unknown.” Provide explicit values in `.constraintguard.yml` if the build artifacts do not expose them reliably.
