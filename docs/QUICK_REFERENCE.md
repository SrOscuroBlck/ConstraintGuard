# Quick Reference

A compact cheat sheet for running ConstraintGuard and configuring constraints.

## CLI commands

### End-to-end run (recommended)
Runs analyzer (scan-build), parses constraints, scores findings, outputs reports.

```bash
constraintguard run \
  --source <repo_path> \
  --build-cmd "<build command>" \
  --config <path/to/.constraintguard.yml> \
  --out <output_dir>
```

### Score existing SARIF (no analyzer execution)
```bash
constraintguard score \
  --sarif <path/to/results.sarif> \
  --config <path/to/.constraintguard.yml> \
  --out <output_dir>
```

### Optional enrichment (bounded)
Enrich top-K findings with evidence bundles and enhanced explanations:

```bash
constraintguard run \
  --source <repo_path> \
  --build-cmd "<build command>" \
  --config <path/to/.constraintguard.yml> \
  --out <output_dir> \
  --enrich topK=10
```

## Output artifacts

- `report.json` – full structured output (constraints, findings, scores, traces)
- `report.md` – readable summary
- `sarif/*.sarif` – analyzer output (if generated)

## YAML configuration essentials

Typical file name: `.constraintguard.yml`

Minimal example:

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
```

Notes:
- Size values may be expressed as `KB`, `MB`, or raw bytes.
- Time values may be expressed as `us`, `ms`, or `s`.
- Any field may be omitted; omitted fields become `unknown` unless derivable from the linker script.

## Severity tiers (default)

ConstraintGuard converts numeric scores to tiers:

- `CRITICAL`: 85–100
- `HIGH`: 70–84
- `MEDIUM`: 40–69
- `LOW`: 0–39

(Exact thresholds may be configurable in the future.)

## Determinism policy

- Expert system scoring is deterministic.
- Enrichment is optional and off by default.
- When enrichment is enabled, deterministic scores remain unchanged unless explicitly configured otherwise.

## Common workflows

Compare constraints on the same codebase:
1) run with tight constraints → output A  
2) run with relaxed constraints → output B  
3) inspect differences in ordering and rule traces

Use in CI later:
- wrap `constraintguard run` in a GitHub Action and publish `report.md` to job summary.
