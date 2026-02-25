# Developer Guide (Technical Details)

This document is intended for new developers joining the ConstraintGuard implementation. It describes the software boundaries, module contracts, data flow, and the “demo-first” plan. It is deliberately practical: it focuses on what you need to implement and how components should interact.

## Project boundaries (what we do and do not do)

### In scope (Demo Phase)
- Run or ingest static analysis findings (initially Clang Static Analyzer, SARIF output).
- Parse constraint inputs (YAML and optionally linker scripts).
- Compute **deterministic** risk scores via an expert-system rule engine.
- Produce JSON/Markdown reports with rule traces and deterministic explanations.
- Provide a CLI that a user can run locally.

### Out of scope (Demo Phase)
- Automated tests (they can be added later).
- GitHub Action packaging (post-demo).
- LLM calls and “agentic” analysis (post-demo).
- Building a new vulnerability detector.

### Post-demo scope
- Agentic Evidence Enrichment: bounded, tool-grounded enrichment per finding.
- CI/CD packaging (Docker + GitHub Action).
- Evaluation harness for paper metrics.

## Minimum viable demo: the contracts that must exist

The demo pipeline needs five main contracts:
1. `HardwareSpec` builder
2. SARIF ingestion (`Vulnerability` list)
3. Expert-system scoring engine
4. Explanation generator (deterministic)
5. Report writer (JSON + Markdown)

### 1) HardwareSpec builder
**Input:** path to YAML, optional path to linker script  
**Output:** `HardwareSpec` + provenance map

Implementation notes:
- All values must be normalized (bytes, microseconds).
- Provenance should indicate the file and source type for each field.
- Missing values must be explicit (defaulted or `None` + “unknown”).

Suggested provenance schema (example):
```json
{
  "ram_size_bytes": {"source": "linker", "path": "mem.ld"},
  "stack_size_bytes": {"source": "yaml", "path": ".constraintguard.yml"},
  "max_interrupt_latency_us": {"source": "default", "value": 0}
}
```

### 2) SARIF ingestion
**Input:** SARIF file(s)  
**Output:** list of `Vulnerability` objects

Implementation notes:
- SARIF can contain multiple runs/results; handle the common shapes robustly.
- Extract at least: ruleId, message, location (file/line/column).
- If function name is available via logical locations, store it (optional but useful).
- Add a lightweight category mapping layer (ruleId → category) to support base scoring.

### 3) Expert-system scoring engine
**Input:** `HardwareSpec`, `Vulnerability`  
**Output:** `RiskItem` (score + tier + fired rules + explanation stub)

Recommended design:
- A registry of rule functions: `List[Rule]`
- Each rule is deterministic: it either fires (returns an adjustment + rationale) or not.
- Score = base(category) + sum(adjustments); clip to 0..100
- Tier derived from score thresholds (configurable later)

Rule interface (suggested):
```python
class RuleResult(NamedTuple):
    rule_id: str
    delta: int
    rationale: str

class Rule(Protocol):
    rule_id: str
    def apply(self, vuln: Vulnerability, spec: HardwareSpec) -> Optional[RuleResult]: ...
```

### 4) Deterministic explanation generator
**Input:** fired rules, vuln, spec summary  
**Output:** a paragraph explanation

Implementation notes:
- Explanations should reference the constraints that triggered escalations.
- Avoid generic “this is severe” language without constraint grounding.
- Use stable templates for each category + rule family.

### 5) Report writer
**Input:** list of `RiskItem` + run metadata  
**Output:** `report.json`, `report.md` and console summary

Implementation notes:
- JSON is the source of truth for later evaluation harness.
- Markdown is meant for humans; keep it readable and brief.
- Include a “constraints summary” section and severity distribution.
- Always include tool version + timestamp + inputs used.

## Suggested module responsibilities

- `parsing/yaml_constraints.py`  
  Reads YAML, validates schema, normalizes units, emits partial spec + provenance.

- `parsing/linker_script.py`  
  Extracts memory regions/symbols when present; emits partial spec + provenance.

- `parsing/normalize.py`  
  Shared unit normalization helpers: sizes, times, identifier lists.

- `parsing/sarif.py`  
  SARIF ingestion into `Vulnerability` objects; includes mapping functions.

- `analysis/clang_runner.py`  
  Executes `scan-build` with SARIF output and collects files. Should be skippable when user provides `--sarif`.

- `scoring/base_scores.py`  
  Base score mapping by category.

- `scoring/rules.py`  
  Rule implementations; keep rule IDs stable.

- `scoring/engine.py`  
  Applies base + rules, produces score/tier and a rule trace.

- `scoring/explain.py`  
  Builds deterministic explanations from rule traces and templates.

- `reporting/json_report.py`, `reporting/md_report.py`, `reporting/console.py`  
  Output formatting.

## Data flow: what to implement first

Implementation order (demo-first):
1. models + normalization utilities
2. YAML constraint parsing → `HardwareSpec`
3. SARIF parsing → `Vulnerability` list (start with a small SARIF sample)
4. scoring engine + 10–15 rules + deterministic explanations
5. report outputs (JSON + Markdown + console)
6. clang runner wrapper (if you don’t already have SARIF samples)

## Post-demo: Agentic Evidence Enrichment (how to integrate safely)

When the demo is stable, enrichment can be added without breaking determinism:

- Add selection policy: top-K by score or changed files list.
- Add evidence bundle builder: code slices + basic call-site search + config references.
- Add agent schema: tags + evidence-cited explanation.
- Attach enrichment output to report without overwriting deterministic score.

Key constraint:
- Enrichment must be optional and bounded; avoid “scan whole repo with an agent.”

## Practical pitfalls to avoid

- Silent defaults for constraints that materially change scoring.
- Unstable rule IDs or changing score thresholds without versioning.
- Allowing the explanation layer to diverge from the score rationale.
- Treating “low actionability” as “false positive” without explicitly defining the term in research outputs.
- Letting post-demo AI layers become the authoritative scorer without an explicit, evaluable mode switch.
