#!/usr/bin/env python3
"""Standalone LLM vulnerability discovery for ConstraintGuard.

Runs inside a scan Docker container after SARIF generation. Reads
/output/findings.sarif, selects the top-K source files (by finding
density), sends each to an LLM asking for embedded-specific issues the
static analyzer cannot detect, and writes /output/discoveries.json.

The script is self-contained — it has no dependency on the constraintguard
package. It requires the `openai` and/or `anthropic` Python packages to be
installed in the image.

Environment variables:
    CONSTRAINTGUARD_LLM_API_KEY    Required. API key for the LLM provider.
    CONSTRAINTGUARD_LLM_PROVIDER   'openai' (default) or 'anthropic'
    CONSTRAINTGUARD_LLM_MODEL      Model name (default: gpt-4o-mini)
    CONSTRAINTGUARD_LLM_TOPK       Number of top files to scan (default: 10)
    CONSTRAINTGUARD_LLM_MAX_FILES  Max total files including escalation (default: 15)
    SOURCE_ROOT                    Root of scanned source (default: /)

Output:
    /output/discoveries.json  — list of discovery dicts, one per candidate
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

SARIF_PATH = pathlib.Path("/output/findings.sarif")
OUTPUT_PATH = pathlib.Path("/output/discoveries.json")
SOURCE_ROOT = pathlib.Path(os.environ.get("SOURCE_ROOT", "/"))
TOP_K = int(os.environ.get("CONSTRAINTGUARD_LLM_TOPK", "10"))
MAX_FILES = int(os.environ.get("CONSTRAINTGUARD_LLM_MAX_FILES", "15"))
MAX_LINES = 3000

# ── Prompts (inlined — no constraintguard dependency) ───────────────────────

_SYSTEM_PROMPT = """\
You are an expert embedded systems security auditor specialising in C/C++ code
running on resource-constrained devices (ARM Cortex-M, RISC-V, ESP32, etc.).

TASK: Scan the provided source file for security vulnerabilities that a static
analyser (Clang Static Analyser / clang-tidy) would NOT detect.

The static analyser already covers these — DO NOT re-report them:
  buffer_overflow, null_deref, leak, use_after_free, integer_overflow,
  format_string, divide_by_zero, uninitialized, deadlock.

FOCUS on issues the static analyser CANNOT detect:
  - race_condition        : shared state accessed from ISR and thread without synchronisation
  - toctou                : time-of-check / time-of-use races
  - incorrect_volatile    : ISR-shared variables missing volatile qualifier
  - blocking_call_in_isr  : blocking API (e.g. xQueueReceive) inside interrupt handler
  - priority_inversion    : lock ordering or ceiling protocol violations
  - unprotected_shared_state: globals/statics modified without critical section
  - stack_vla             : variable-length arrays on stack in constrained environments
  - timing_side_channel   : data-dependent timing leakage
  - logic_error           : incorrect algorithm, wrong condition, swappable parameters

RULES:
1. Only report issues NOT already listed in the "Known findings" section.
2. Cite exact line numbers from the numbered source listing.
3. Return ONLY valid JSON — no prose before or after the JSON object.
4. Schema:
   {"discoveries": [{"type": "string", "severity_rationale": "string",
     "file_path": "string", "start_line": int, "end_line": int,
     "evidence_citation": "string"}]}
5. If no new issues are found, return: {"discoveries": []}
"""

_USER_TEMPLATE = """\
## File Under Audit

**Path:** {file_path}

## Known Findings (static analyser already reported — DO NOT re-report)

{known_findings}

## Source Code (line-numbered)

```c
{numbered_source}
```

Audit the code above. Return JSON with any NEW vulnerabilities not listed above.\
"""


# ── SARIF helpers ────────────────────────────────────────────────────────────

def _load_sarif(path: pathlib.Path) -> list[dict]:
    """Return list of SARIF result dicts."""
    data = json.loads(path.read_text())
    results = []
    for run in data.get("runs", []):
        results.extend(run.get("results", []))
    return results


def _sarif_file_path(result: dict) -> str | None:
    try:
        return result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    except (KeyError, IndexError):
        return None


def _sarif_line(result: dict) -> int | None:
    try:
        return result["locations"][0]["physicalLocation"]["region"]["startLine"]
    except (KeyError, IndexError):
        return None


def _top_k_files(results: list[dict], k: int) -> list[str]:
    """Return up to k unique file paths ordered by finding count descending."""
    from collections import Counter
    counts: Counter = Counter()
    for r in results:
        fp = _sarif_file_path(r)
        if fp:
            counts[fp] += 1
    return [fp for fp, _ in counts.most_common(k)]


# ── Prompt builder ───────────────────────────────────────────────────────────

def _build_prompt(file_path: str, content: str, known: list[dict]) -> str:
    lines = content.splitlines()
    truncated = False
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]
        truncated = True

    numbered = "\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))
    if truncated:
        numbered += f"\n[... truncated at {MAX_LINES} lines ...]"

    if known:
        known_lines = [
            f"- Line {_sarif_line(r)}: [{r.get('ruleId', '?')}] "
            f"{r.get('message', {}).get('text', '')[:120]}"
            for r in known
        ]
        known_str = "\n".join(known_lines)
    else:
        known_str = "(none — no static analyser findings in this file)"

    return _USER_TEMPLATE.format(
        file_path=file_path,
        known_findings=known_str,
        numbered_source=numbered,
    )


# ── LLM clients ─────────────────────────────────────────────────────────────

def _call_openai(system: str, user: str, api_key: str, model: str) -> dict:
    import openai
    client = openai.OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
    )
    return json.loads(resp.choices[0].message.content)


def _call_anthropic(system: str, user: str, api_key: str, model: str) -> dict:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = resp.content[0].text.strip()
    # Strip markdown fences if present
    if text.startswith("```"):
        text = "\n".join(text.splitlines()[1:])
        if text.endswith("```"):
            text = text[:-3].strip()
    return json.loads(text)


def _call_llm(system: str, user: str, api_key: str, model: str, provider: str) -> list[dict]:
    """Call LLM and return list of raw discovery dicts."""
    try:
        if provider == "anthropic":
            result = _call_anthropic(system, user, api_key, model)
        else:
            result = _call_openai(system, user, api_key, model)
        return result.get("discoveries", [])
    except Exception as exc:
        print(f"    LLM call failed: {exc}", file=sys.stderr)
        return []


# ── Discovery loop ───────────────────────────────────────────────────────────

def _normalize_path(path: str) -> str:
    """Strip leading slash so paths match SARIF URIs (src/freertos/...)."""
    return path.lstrip("/")


def run_discovery(api_key: str, model: str, provider: str, results: list[dict]) -> list[dict]:
    seed_files = _top_k_files(results, TOP_K)
    # Map file_path -> list of SARIF results for that file
    by_file: dict[str, list[dict]] = {}
    for r in results:
        fp = _sarif_file_path(r)
        if fp:
            by_file.setdefault(fp, []).append(r)

    queue: list[tuple[str, int]] = [(fp, 0) for fp in seed_files]
    scanned: set[str] = set()
    all_discoveries: list[dict] = []

    while queue and len(scanned) < MAX_FILES:
        file_path, depth = queue.pop(0)
        if file_path in scanned:
            continue

        # Resolve absolute path inside container
        abs_path = SOURCE_ROOT / file_path
        if not abs_path.exists():
            print(f"  [discover] Not found: {abs_path}", file=sys.stderr)
            scanned.add(file_path)
            continue

        print(f"  [discover] Scanning (depth={depth}): {file_path}")
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"  [discover] Read error: {exc}", file=sys.stderr)
            scanned.add(file_path)
            continue

        known = by_file.get(file_path, [])
        user_prompt = _build_prompt(file_path, content, known)
        discoveries = _call_llm(_SYSTEM_PROMPT, user_prompt, api_key, model, provider)
        print(f"  [discover] → {len(discoveries)} candidate(s)")

        # Normalise file_path in each discovery to match SARIF URIs
        for d in discoveries:
            if "file_path" in d:
                d["file_path"] = _normalize_path(d["file_path"])

        all_discoveries.extend(discoveries)
        scanned.add(file_path)

        # Escalation: queue files referenced in discoveries (depth + 1)
        if depth < 2:
            for d in discoveries:
                ref = d.get("file_path", "")
                if ref and ref != file_path and ref not in scanned:
                    if not any(ref == q[0] for q in queue):
                        queue.append((ref, depth + 1))
                        print(f"  [discover] Escalating to: {ref}")

    return all_discoveries


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    api_key  = os.environ.get("CONSTRAINTGUARD_LLM_API_KEY", "")
    model    = os.environ.get("CONSTRAINTGUARD_LLM_MODEL", "gpt-4o-mini")
    provider = os.environ.get("CONSTRAINTGUARD_LLM_PROVIDER", "openai").lower()

    if not api_key:
        print("[discover] No LLM API key — skipping discovery. Set CONSTRAINTGUARD_LLM_API_KEY to enable.")
        OUTPUT_PATH.write_text("[]")
        return

    if not SARIF_PATH.exists():
        print(f"[discover] SARIF not found at {SARIF_PATH} — skipping.")
        OUTPUT_PATH.write_text("[]")
        return

    print(f"[discover] Starting file-level LLM discovery (provider={provider}, model={model})")
    results = _load_sarif(SARIF_PATH)
    print(f"[discover] {len(results)} SARIF findings across "
          f"{len(set(filter(None, (_sarif_file_path(r) for r in results))))} files")

    discoveries = run_discovery(api_key, model, provider, results)

    OUTPUT_PATH.write_text(json.dumps(discoveries, indent=2))
    print(f"[discover] Done. {len(discoveries)} candidate(s) written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
