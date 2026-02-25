# Architecture

This document describes ConstraintGuard’s architecture with an emphasis on the **Phase 1 Demo (Deterministic Expert System)**. Phase 2 introduces optional agentic enrichment that is bounded and evidence-grounded.

## Design principles

1. **Detection is tool-based**  
   ConstraintGuard does not attempt to “discover vulnerabilities” by LLM reasoning. It consumes findings from established tools (initially Clang Static Analyzer via SARIF).

2. **Prioritization is constraint-aware**  
   Risk is conditioned on embedded constraints (memory envelope, interrupt latency budgets, safety-critical context).

3. **Determinism first**  
   The demo’s prioritization is a reproducible expert system: same inputs → same outputs. This supports research defensibility and reliable CI behavior.

4. **Optional augmentation is bounded and grounded** (post-demo)  
   Agentic enrichment operates only on a limited subset (top-K or changed files). It must cite concrete evidence (file + line ranges) gathered by deterministic tooling.

## Pipeline overview (Phase 1 Demo)

### 1) Constraint ingestion
Inputs:
- `.constraintguard.yml` (explicit intent; recommended)
- `.ld` linker script (authoritative memory regions/symbols)

Outputs:
- `HardwareSpec` (normalized units)
- `provenance` (where each field came from)
- explicit missing/unknown markers (no silent assumptions)

### 2) Static analysis detection
Inputs:
- repository path
- build command

Process:
- run Clang Static Analyzer (typically via `scan-build`) and capture SARIF output

Outputs:
- one or more SARIF files

Alternative:
- ingest a pre-generated SARIF file to support environments where `scan-build` is unavailable.

### 3) SARIF parsing
Inputs:
- SARIF file(s)

Outputs:
- list of `Vulnerability` objects with:
  - rule ID and message
  - location (file/line/column when available)
  - function name when available
  - optional CWE/category mapping

### 4) Deterministic expert scoring
Inputs:
- `Vulnerability`
- `HardwareSpec`

Outputs:
- numeric score (0–100)
- severity tier (e.g., CRITICAL/HIGH/MEDIUM/LOW)
- **rule trace**: which rules fired and why, referencing constraints explicitly

### 5) Reporting
Outputs:
- console summary
- JSON report (full fidelity)
- Markdown report (human friendly)

## Key domain objects

### HardwareSpec
Represents the target environment in normalized units.

Typical fields:
- `platform`: string identifier
- `ram_size_bytes`, `flash_size_bytes`
- `stack_size_bytes`, `heap_size_bytes`
- `max_interrupt_latency_us`
- `critical_functions`: list of identifiers
- `safety_level`: categorical string (e.g., ISO 26262 context)

### Vulnerability
Represents a finding from an analyzer (source-agnostic).

Typical fields:
- `rule_id`
- `message`
- `path`, `line`, `column`
- `function` (optional)
- `category` (normalized bucket)
- `cwe` (optional)

### RiskItem / ReportEntry
Represents a scored finding plus trace and explanation.

Typical fields:
- `score`
- `tier`
- `fired_rules`: list of `{rule_id, rationale, evidence}`
- `explanation` (deterministic in demo phase)

## Expert system scoring model

The scoring layer is intentionally simple to keep it auditable and suitable for ablation experiments.

- A **base score** is assigned by category (buffer overflow vs leak vs null deref, etc.).
- **Rule adjustments** are applied based on constraint conditions and context flags.

Example rule families (demo target: ~10–15 rules):
- memory tightness: small stack/heap/RAM escalates memory bugs
- interrupt context: ISR-related contexts escalate latency and correctness risks
- safety criticality: marked critical functions escalate severity
- real-time hazards: blocking operations under low interrupt budget escalates
- lifetime exhaustion: leaks + long-running tasks under small heap escalates

The expert system must emit a rule trace for each score:
- “Rule R3 fired because stack_size_bytes < 2048 and category == overflow”
- “Rule R7 fired because function in critical_functions”

## Post-demo: Agentic Evidence Enrichment (optional)

Agentic enrichment is not “comprehensive code analysis.” It is a bounded investigation loop that attaches evidence-backed context to a small set of findings.

### Selection policy
- top-K findings by deterministic score, and/or
- findings in changed files for a PR context

### Evidence bundle
Collected deterministically from the repo:
- local code slice around finding
- enclosing function body (when feasible)
- simple caller search (text-based or tags-based)
- relevant config references
- compilation flags (when available)

### Agent outputs (strict contract)
- structured tags (ISR-likely, heap-touching, blocking-call-present, etc.)
- explanation that cites evidence bundle entries
- optional remediation notes

The default mode does not override deterministic scoring. If an override mode is ever added, it must be explicitly enabled and evaluated separately.
