# ConstraintGuard

ConstraintGuard is a **constraint-aware security prioritization** tool for embedded C/C++ projects. It consumes static analysis findings (initially **Clang Static Analyzer** exported as **SARIF**) and re-ranks them using a **target constraint profile** (e.g., RAM/Flash limits, stack/heap budgets, interrupt latency budgets, and safety-critical context). The goal is to reduce *low-actionability* alert noise and surface findings that are genuinely high-risk **for the specific embedded target**.

ConstraintGuard is designed around a strict separation of responsibilities:

- **Detection is tool-based** (e.g., Clang Static Analyzer). ConstraintGuard does not attempt to replace analyzers.
- **Prioritization is deterministic by default** via an expert system, enabling reproducibility and auditability.
- **Agentic Evidence Enrichment is optional** and bounded (e.g., top-K findings) to improve explanations and context tags without turning into expensive “scan the whole repo” automation.

## What ConstraintGuard does

- Runs (or ingests) static analysis and loads findings from SARIF.
- Extracts a structured constraint profile (**HardwareSpec**) from:
  - an optional YAML file (project intent and safety context), and
  - a linker script (authoritative memory regions when available).
- Applies deterministic scoring rules (expert system) to produce:
  - a numeric score (0–100),
  - a severity tier,
  - a rule trace (why the score changed under the constraints).
- Generates human- and machine-friendly reports:
  - console summary,
  - JSON report,
  - Markdown report.

## What ConstraintGuard intentionally does **not** do

- It does **not** claim to find all vulnerabilities in a codebase.
- It does **not** replace compilers, sanitizers, static analyzers, or SAST platforms.
- It does **not** require LLM access to produce its core ranking.
- It does **not** perform “comprehensive LLM scanning” of the entire repository.

## Core concepts

**HardwareSpec**  
A normalized profile of constraints and context for the target platform (units normalized, provenance tracked). Example fields include RAM/Flash size, stack/heap budgets, interrupt latency budgets, safety level, and critical functions.

**Vulnerability**  
A normalized representation of a SARIF finding (rule ID, message, location, optional logical location).

**Expert system scoring**  
A deterministic rule registry. Each finding receives a base score from its category and is adjusted by rule firings conditioned on HardwareSpec. Each firing contributes an auditable explanation fragment.

**Agentic Evidence Enrichment (optional)**  
A bounded, tool-grounded enrichment step that:
- collects local evidence bundles (code slices, symbol references, relevant config excerpts),
- generates context tags and richer explanations with citations back to evidence,
- does not alter deterministic scores by default.

## Repository layout (planned)

- `constraintguard/`
  - `cli/` – CLI entry points and argument parsing
  - `models/` – typed models (HardwareSpec, Vulnerability, RiskReport)
  - `parsers/` – YAML, linker script, SARIF ingestion
  - `analyzers/` – runner wrappers (scan-build / clang)
  - `scoring/` – expert system rules and scoring engine
  - `reporting/` – JSON/Markdown/console outputs
  - `enrichment/` – optional evidence bundle builder and agent adapters
- `examples/` – demo projects and sample configs
- `docs/` – documentation files listed below

## Documentation

- **ARCHITECTURE.md** – system architecture, data flow, module responsibilities, and interfaces.
- **GETTING_STARTED.md** – installation and local manual-run instructions.
- **QUICK_REFERENCE.md** – CLI and configuration cheat sheet.
- **TECHNICAL_DETAILS.md** – implementation details, schemas, rule design, SARIF mapping, determinism and evidence contracts.

## License

Add your chosen license here (e.g., MIT/Apache-2.0). Until specified, treat this repository as “all rights reserved” for external distribution.
