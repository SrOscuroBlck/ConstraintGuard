# Technical Details (Developer Guide)

This document is for developers implementing ConstraintGuard. It explains the main technical decisions, data contracts, and implementation expectations.

## 1. Deterministic expert system: why it is the core

ConstraintGuard’s research claim depends on reproducible results. The expert system scorer is therefore the “source of truth” for prioritization. It must be:
- **deterministic**: same inputs → same outputs,
- **auditable**: every score change is justified by explicit rule firings,
- **constraint-referenced**: rule rationales cite the specific constraint fields used.

If an optional LLM is used, it may enhance explanations and tags but must not silently override the deterministic scorer by default.

## 2. Data model contracts

### 2.1 HardwareSpec

A normalized constraint profile with explicit units and uncertainty handling.

Recommended fields (extendable):
- `platform: str | None`
- `ram_size_bytes: int | None`
- `flash_size_bytes: int | None`
- `stack_size_bytes: int | None`
- `heap_size_bytes: int | None`
- `max_interrupt_latency_us: int | None`
- `critical_functions: list[str]`
- `safety_level: str | None`

Provenance:
- per-field origin: `{source_type, source_path, extraction_note}` where source_type ∈ {yaml, ld, default, unknown}.

### 2.2 Vulnerability

Normalized finding representation:
- `tool: str`
- `rule_id: str`
- `message: str`
- `path: str`
- `start_line: int | None`
- `start_col: int | None`
- `function: str | None`
- `cwe: str | None`
- `category: str` (derived)

### 2.3 RuleFiring / RiskItem / RiskReport

`RuleFiring`:
- `rule_id: str`
- `delta: int`
- `rationale: str`
- `constraints_used: list[str]`

`RiskItem`:
- `vulnerability: Vulnerability`
- `base_score: int`
- `final_score: int`
- `tier: str`
- `rule_firings: list[RuleFiring]`
- `explanation: str` (deterministic)
- `remediation: str` (deterministic template)
- `enrichment: dict | None` (optional)

`RiskReport`:
- `run_metadata` (versions, timestamps, commands)
- `hardware_spec`
- `provenance`
- `summary` (counts by tier, top-K identifiers)
- `items: list[RiskItem]`

## 3. Constraint parsing and normalization

### 3.1 YAML parsing

YAML should represent “intent” clearly and override unknowns. Normalization rules:
- sizes: accept `B`, `KB`, `MB`, `GB` (case-insensitive); compute bytes
- times: accept `us`, `ms`, `s`; compute microseconds

If invalid strings are provided:
- reject the run with a clear error message (do not guess).

### 3.2 Linker script parsing

Linker scripts vary widely. For the initial implementation:
- support basic `MEMORY { ... }` parsing for RAM/FLASH region sizes
- support known symbols for stack/heap when present (project-dependent)

If the script cannot be parsed reliably:
- record `unknown` and rely on YAML overrides.

## 4. SARIF ingestion and category mapping

SARIF extraction must be robust:
- gather `ruleId`, `message`, and at least one physical location
- prefer absolute or repository-relative paths consistently

Category mapping:
- implement a small mapping table `rule_id → category` (and `category → base_score`)
- treat the mapping as configuration, not hard-coded magic, so it can evolve

When no mapping exists:
- assign category `unknown` with conservative base score and log the missing mapping.

## 5. Expert system scoring design

### 5.1 Scoring function

A simple additive model is preferred for interpretability:
- base score from category
- apply rule deltas in deterministic order
- clip to [0, 100]
- compute tier from thresholds

### 5.2 Rule registry

Each rule should be a pure function:
- Inputs: `Vulnerability`, `HardwareSpec`
- Output: `RuleFiring | None`

Rules must:
- reference explicit signals,
- be small and testable,
- include a rationale string that identifies why it fired.

Example rule families:
- Memory tightness: overflow/leak escalations under small stack/heap/RAM
- Interrupt context: ISR-related escalations when latency budgets exist
- Safety criticality: escalations for findings in marked critical functions
- Real-time hazards: blocking calls in timing-sensitive code paths (best-effort in demo)
- Lifetime exhaustion: leaks in long-running contexts (requires conservative assumptions)

### 5.3 Severity tiering

Default tiers:
- CRITICAL: 85–100
- HIGH: 70–84
- MEDIUM: 40–69
- LOW: 0–39

Tier thresholds should be constants in one place (configurable later).

## 6. Reporting details

### 6.1 JSON report
Must include:
- normalized constraints + provenance
- ranked findings with score, tier, rule firings, deterministic explanation
- stable identifiers per finding (for caching and evaluation)

### 6.2 Markdown report
Must include:
- constraints summary
- counts by tier
- top prioritized findings with brief justification
- pointers to full JSON details

## 7. Agentic Evidence Enrichment (optional) — implementation constraints

### 7.1 Bounded scope
Enrichment must operate on a selected subset:
- top-K findings,
- findings in changed files (future CI integration),
- or score threshold.

### 7.2 Evidence bundle contract
Before calling an agent:
- collect local evidence: file slices, function body, basic call-site hints, config excerpts.
- store evidence as structured artifacts with path + line ranges.

### 7.3 Agent output schema
Agent outputs must be structured:
- context tags (booleans / enums),
- enriched explanation,
- citations to evidence artifacts.

### 7.4 Non-goals
Enrichment must not:
- claim to be comprehensive,
- silently change expert-system scores by default,
- introduce uncontrolled stochastic ranking in the core pipeline.

## 8. Recommended implementation order (engineering)

A sensible build order is:
1) models + CLI skeleton
2) YAML parser + normalization
3) SARIF ingestion
4) expert system scoring
5) reporting
6) analyzer runner integration
7) example repo + configs
8) optional enrichment scaffolding (selection + evidence bundle)

## 9. Quality bar and conventions

- Prefer typed models (dataclasses or Pydantic) for validation.
- Fail loudly on invalid config; fail gracefully on partial data (unknown constraints).
- Log decisions that affect scoring (constraint origins, missing mappings, rule firings).
- Keep the deterministic pipeline free from external API dependencies.
