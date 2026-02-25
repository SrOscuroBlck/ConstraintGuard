# Quick Reference

This page is a compact reference for day-to-day usage during the Demo Phase.

## CLI (proposed)

### Run end-to-end analysis
```bash
constraintguard \
  --source <path-to-repo> \
  --config <path-to-.constraintguard.yml> \
  --build-cmd "<build command>" \
  --out <output-dir>
```

### Ingest existing SARIF (skip running analyzer)
```bash
constraintguard \
  --source <path-to-repo> \
  --config <path-to-.constraintguard.yml> \
  --sarif <path-to-findings.sarif> \
  --out <output-dir>
```

### Show top findings only
```bash
constraintguard ... --top 10
```

## Output files (demo target)

- `constraints.json` — normalized constraints + provenance
- `report.json` — full scored findings, fired rules, explanations
- `report.md` — human-readable prioritized report

## HardwareSpec normalization

Accepted size formats (examples):
- `2048B`, `2KB`, `20KB`, `1MB`
Accepted time formats:
- `50us`, `1ms`, `0.1ms`

## Rule trace expectations (demo)
Every scored finding should include a “fired rules” list with:
- rule identifier (stable name)
- rationale referencing the specific constraint value that triggered it

Example (conceptual):
- `MEM_STACK_TIGHT`: “stack_size_bytes=2048 < 4096 and category=overflow”
- `SAFETY_CRITICAL_FN`: “function=safety_shutdown is marked critical”

## Severity tiers (example)
A simple default mapping (adjustable later):
- 85–100: CRITICAL
- 70–84: HIGH
- 40–69: MEDIUM
- 0–39: LOW

## Post-demo flags (reserved)
These flags are future-facing and can be added after the deterministic demo is stable:
- `--enrich topK=20`
- `--enrich changed-files`
- `--enrich-timeout 30s`
- `--cache-dir <path>`
