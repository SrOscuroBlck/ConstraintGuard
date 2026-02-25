# ConstraintGuard

ConstraintGuard is a **constraint-aware vulnerability prioritization** tool for embedded C/C++ projects. It keeps **detection tool-based** (e.g., Clang Static Analyzer) and makes **prioritization deterministic and reproducible** via an expert-system score that incorporates realistic embedded constraints (RAM/Flash, stack/heap, interrupt latency budgets, safety-critical context).

The project is built in two phases:

- **Phase 1 (Demo): Deterministic Expert System** — a manually runnable CLI that:
  - parses constraints from `.constraintguard.yml` and/or linker scripts (`.ld`),
  - runs (or ingests) Clang Static Analyzer SARIF findings,
  - scores findings deterministically with rule traces,
  - produces ranked reports (console + JSON + Markdown).

- **Phase 2 (Post-Demo): Agentic Evidence Enrichment (Optional)** — a bounded, tool-grounded augmentation layer that enriches **top-K** findings (or findings in changed files) with evidence bundles, context tags, and higher-quality explanations. It does **not** replace static analysis and does **not** override deterministic scoring by default.

## Why this exists

Static analysis severity is typically hardware-agnostic. In embedded systems, the same bug can be trivial on a device with abundant resources and catastrophic on a microcontroller with kilobytes of stack, tight interrupt budgets, or safety-critical execution paths. ConstraintGuard encodes that reality explicitly.

## Repository layout (recommended)

```
constraintguard/
  __init__.py
  cli.py
  models/
    hardware_spec.py
    vulnerability.py
    report.py
  parsing/
    yaml_constraints.py
    linker_script.py
    normalize.py
    sarif.py
  analysis/
    clang_runner.py
  scoring/
    base_scores.py
    rules.py
    engine.py
    explain.py
  reporting/
    json_report.py
    md_report.py
    console.py
examples/
  demo_project/
docs/
  Architecture.md
  GettingStarted.md
  QuickReference.md
  DeveloperGuide.md
```

This layout is a guide; the demo can start smaller and grow into the structure above.

## Core inputs/outputs

### Inputs
- Embedded codebase (C/C++)
- Build command (for running Clang analyzer), e.g. `make`, `cmake --build .`, `ninja`
- Constraints, via:
  - `.constraintguard.yml` (recommended for explicit intent), and/or
  - linker script (`.ld`) (authoritative memory regions / symbols)

### Outputs
- **Console summary**: severity distribution, top findings
- **JSON report**: full run metadata, constraints + provenance, findings, scores, fired rules
- **Markdown report**: human-friendly prioritized list and constraint summary

## Status and roadmap

- ✅ Demo phase targets a deterministic expert system end-to-end pipeline.
- ⏭️ Post-demo adds optional agentic evidence enrichment and CI integration (GitHub Action).

See:
- `docs/GettingStarted.md` for the demo run flow
- `docs/Architecture.md` for system design
- `docs/QuickReference.md` for CLI + config snippets
- `docs/DeveloperGuide.md` for implementation details and module contracts

## License
Choose a license before publishing publicly (MIT/Apache-2.0 are common for research tooling).
