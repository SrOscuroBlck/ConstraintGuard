# ConstraintGuard Architecture

This document describes ConstraintGuard’s architecture at the component and interface level. The system is built to keep detection and prioritization separate, providing a reproducible deterministic baseline and an optional bounded AI enrichment layer.

## Architectural principles

1. **Detection is external; prioritization is internal.**  
   ConstraintGuard consumes analyzer outputs and focuses on re-ranking findings under target constraints.

2. **Determinism by default.**  
   The expert system scorer must be reproducible. Given identical inputs, it produces identical scores and rule traces.

3. **Constraint provenance is first-class.**  
   For each constraint field, the system records where it came from (YAML, linker script, defaults, or unknown).

4. **Optional AI is bounded and tool-grounded.**  
   Agentic Evidence Enrichment, when enabled, operates on a limited set of findings and must cite local evidence. It does not replace analyzers and does not silently override deterministic scoring.

## High-level data flow

1. **Constraint ingestion**
   - Input: optional `.constraintguard.yml` and/or linker script `.ld`
   - Output: `HardwareSpec` + `ConstraintProvenance`

2. **Static analysis**
   - Input: source repository + build command (or pre-generated SARIF)
   - Output: SARIF file(s)

3. **Finding ingestion**
   - Input: SARIF
   - Output: list of `Vulnerability` objects + category/CWE mapping

4. **Deterministic prioritization**
   - Input: `HardwareSpec` + `Vulnerability[]`
   - Output: `RiskReport` (ranked findings) with rule traces

5. **(Optional) Agentic Evidence Enrichment**
   - Input: selected findings + local repository context + `HardwareSpec` + rule traces
   - Output: evidence bundles + context tags + enriched explanations (with citations)

6. **Reporting**
   - Output: console summary + JSON report + Markdown report

## Core modules

### 1) CLI (`constraintguard/cli`)
Responsibilities:
- Parse CLI arguments and validate required inputs.
- Orchestrate the run: parse constraints → run/ingest SARIF → score → report.
- Enforce determinism defaults (no enrichment unless explicitly enabled).

Key interfaces:
- `constraintguard run --source <path> --build-cmd "<cmd>" --config <yml> --out <dir>`
- `constraintguard score --sarif <path> --config <yml> --out <dir>` (optional)

### 2) Models (`constraintguard/models`)
Primary models:
- `HardwareSpec`: normalized constraints + context (bytes, microseconds).
- `ConstraintProvenance`: per-field origin metadata.
- `Vulnerability`: normalized SARIF finding representation.
- `RuleFiring`: rule id, weight/delta, rationale, referenced constraints.
- `RiskItem`: vulnerability + score + tier + rule trace + explanation.
- `RiskReport`: run metadata + constraints summary + ranked list + aggregates.

### 3) Constraint parsers (`constraintguard/parsers`)
- YAML parser:
  - captures “intent” fields: safety level, critical functions, platform metadata.
  - allows explicit overrides for memory/timing budgets when known.
- Linker script parser:
  - extracts memory regions for RAM/FLASH when feasible.
  - extracts stack/heap sizes if symbols are present.
- Normalization layer:
  - converts sizes to bytes, times to microseconds.
  - validates ranges and records “unknown” where not derivable.

### 4) Analyzer runner (`constraintguard/analyzers`)
- Wraps `scan-build` to produce SARIF.
- Handles output directories and errors.
- Does not attempt to interpret results beyond producing SARIF files.

### 5) SARIF ingestion (`constraintguard/parsers/sarif`)
Responsibilities:
- Parse SARIF into `Vulnerability` instances.
- Extract locations reliably: file path, line/column, logical location when present.
- Map tool rule IDs into coarse categories to drive scoring (e.g., overflow, leak, null deref).

### 6) Scoring engine (`constraintguard/scoring`)
- Rule registry (deterministic):
  - each rule is a pure function of `(vulnerability, hardware_spec) → maybe RuleFiring`.
- Scorer:
  - base score by category,
  - apply rule firings in a stable order,
  - clip and tier scores,
  - build deterministic explanations from fired rules.

Rules are intentionally limited and interpretable. The system is designed so that new rules can be added without changing the core pipeline contracts.

### 7) Reporting (`constraintguard/reporting`)
Outputs:
- Console summary: totals by tier + top-K list.
- JSON report: complete structured output for evaluation and later tooling.
- Markdown report: shareable summary plus key findings.

### 8) Enrichment (`constraintguard/enrichment`) — optional
Agentic Evidence Enrichment is a separate module and must be explicitly enabled.

Components:
- Selection policy:
  - `top-K`, `changed-files`, `score-threshold`, and time budget.
- Evidence builder:
  - collects local code slices, function context, call-site hints, and config excerpts.
- Agent adapter:
  - generates structured tags + enriched explanation with citations to evidence.
- Cache:
  - keyed by finding identity + code hash + constraint profile hash.

## Interfaces and contracts

### Deterministic contract
If enrichment is disabled:
- identical inputs must produce identical outputs (scores, tiers, traces, report ordering).

### Evidence contract (enrichment)
If enrichment is enabled:
- any claim in enriched output must cite a local evidence artifact (file + line range or captured snippet id).
- enrichment must not fail the entire run; failures are localized to findings.

## Extensibility points

- Add analyzers: implement additional SARIF ingestion mappings.
- Add constraint sources: Kconfig, devicetree, RTOS config (future).
- Add rule families: new deterministic rules tied to explicit signals.
- Add agent capabilities: richer context tags and remediation assistance, bounded by policy.
