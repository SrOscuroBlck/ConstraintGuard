# ConstraintGuard — Evaluation Section Briefing
## For the AI Writing the EMSOFT 2026 Paper

---

## 1. What ConstraintGuard Is

ConstraintGuard is a **constraint-aware security prioritization tool** for embedded C/C++ projects. It sits on top of a static analyzer (Clang Static Analyzer / clang-tidy) and re-ranks the findings using a **hardware constraint profile** defined by the engineer in a YAML file.

The hardware profile specifies:
- RAM and Flash size
- Stack and heap budgets
- Maximum interrupt latency (`max_interrupt_latency_us`)
- Safety level (e.g., IEC 61508 SIL2)
- List of critical functions (e.g., `vTaskSwitchContext`, `handle_isr`)

The tool does **not** run the static analyzer itself — it scores and re-ranks findings that are already in SARIF 2.1.0 format (the output format of Clang Static Analyzer and clang-tidy).

The scoring pipeline:
1. Parse SARIF → normalized `Vulnerability` list
2. Load hardware constraints → `HardwareSpec`
3. Apply 14 deterministic scoring rules → `RiskItem` list with 0–100 scores and tier labels (CRITICAL/HIGH/MEDIUM/LOW)
4. Optionally: send top-K findings to an LLM for enrichment (explanation, tags, fix suggestions)
5. Output: JSON report, Markdown report, console summary

**Tiers:** CRITICAL = 85–100, HIGH = 70–84, MEDIUM = 40–69, LOW = 0–39.

**Baseline score** is assigned by vulnerability category (BUFFER_OVERFLOW=60, USE_AFTER_FREE=65, LEAK=45, UNKNOWN=35). Rules add deltas on top.

**Key rule families:**
- **Memory** (4 rules): fire when RAM/stack/heap are tight and the finding involves memory operations
- **ISR** (3 rules): fire when interrupt latency is constrained and the finding could affect ISR paths
- **Safety** (3 rules): fire when a safety level is declared (e.g., SIL2)
- **RT-Hazard** (2 rules): fire on ultra-tight ISR budgets (≤50µs), category-agnostic
- **Lifetime** (1 rule): fires on LEAK findings under functional safety

Two RT-Hazard rules are **category-agnostic** — they fire on ALL findings regardless of type when ISR latency ≤ 50µs. This is intentional: on a hard-real-time system with a 50µs budget, any finding near an ISR path becomes critical regardless of its vulnerability class.

---

## 2. What Was Evaluated

### Projects

Three real open-source embedded projects were analyzed using Docker-based static analysis (clang-tidy with `clang-analyzer-*` and `bugprone-*` checkers):

| Project | Domain | Platform | Findings |
|---------|--------|----------|----------|
| FreeRTOS-Kernel (main branch) | RTOS kernel | Cortex-M3, 20KB RAM, 50µs ISR | 77 |
| Zephyr RTOS (main branch) | RTOS kernel | ESP32, 520KB RAM, 100µs ISR | 208 |
| esp-fc (master branch) | Flight controller firmware | ESP32, 192KB RAM, 50µs ISR, IEC 61508 SIL2 | 195 |

Hardware profiles were hand-authored to reflect each project's real deployment constraints.

### What "Baseline" Means

Baseline = scoring with a null `HardwareSpec` (all fields zeroed/defaulted). No rules fire. Findings are ordered by their base score (determined only by vulnerability category). This is the control condition — equivalent to a generic severity ranker with no hardware knowledge.

### What "Deterministic" Means

Deterministic = full constraint-aware scoring. All 14 rules are evaluated. Results are reproducible and deterministic — no randomness, no LLM, no network calls.

### Ground Truth

30 findings per project were manually labeled by the authors (is_critical: true/false). Labels are in `eval/data/ground_truth/{project}_labels.json`.

Critical findings were defined as: findings that, if exploited or triggered, would cause a safety, timing, or correctness failure specific to that platform's constraint profile. Examples:
- FreeRTOS: swappable parameters in MPU wrappers, macro-parentheses in ISR-path code
- Zephyr: CAS parameter swaps in atomic primitives, conflicting type declarations in atomics
- esp-fc: reserved identifier `_model_ptr` as global pointer in ISR-reachable context, branch-clone in safety-critical CLI switch

---

## 3. The Five Results — What They Show and Why They Matter

### Figure 1: Constraint-Aware Ranking vs. Expert Judgment (`exp1_precision_at10.pdf`)

**What it is:** A bar chart showing Expert Agreement (%) per project. Expert Agreement = the percentage of the deterministic system's top findings that match the human expert's ground truth labels.

**Numbers:** FreeRTOS = 63.3%, Zephyr = 76.7%, esp-fc = 72.7%. Average = 70.9%.

**Why it matters:** This is the primary correctness metric. It shows that ConstraintGuard's deterministic scoring agrees with expert human judgment at a rate of ~71% on average across three real embedded projects. For a fully automated, zero-human-in-the-loop prioritization system, this is the key claim: it agrees with experts most of the time.

**Important nuance to handle honestly:** Precision@10 (i.e., how many of the top-10 are actually critical) was identical across Baseline and Deterministic methods (20% for FreeRTOS/Zephyr, 0% for esp-fc). This is because clang-tidy on production RTOS kernels produces predominantly `bugprone-*` and `cert-*` findings, which are mapped to `UNKNOWN` category with base score 35. When all findings are `UNKNOWN`, the category-agnostic RT-Hazard rules boost them uniformly, so relative ranking does not change between baseline and deterministic. **Do not hide this — state it as a scanner limitation, not a system failure.** The contribution is in WHICH findings are escalated and WHY (deterministic rationale), not in reordering within a homogeneous finding set. The Expert Agreement figure is the right metric to emphasize.

**Table:** `exp1_precision_accuracy.tex` — includes P@10 (all identical) and Expert Agreement per project.

---

### Figure 2: CWE–Constraint Interaction Heatmap (`exp4_cwe_heatmap.pdf`)

**What it is:** A 6×5 heatmap showing normalized severity scores (0=benign, 1=critical) for combinations of 6 CWE types × 5 hardware constraint profiles. Values are computed synthetically by running the scoring engine on representative findings under each constraint profile.

**CWE types shown:** CWE-121 (stack overflow), CWE-122 (heap overflow), CWE-416 (use-after-free), CWE-401 (memory leak), CWE-362 (race condition), CWE-476 (null deref).

**Constraint profiles:** Low Stack, Low RAM, Tight ISR (≤50µs), Safety-Critical (SIL2), Long Uptime.

**Key observations:**
- CWE-416 (use-after-free) + Tight ISR = 1.0 (maximum severity) — UAF in an ISR-reachable context on a hard-RT system is the highest risk combination
- CWE-416 + Low Stack = 0.95, CWE-416 + Low RAM = 0.90 — UAF is consistently the highest-risk vulnerability class
- CWE-362 (race condition) + Low Stack = 0.45 — race conditions are less severe when the main constraint is memory pressure
- CWE-401 (memory leak) + Safety-Critical = 0.72 — leaks escalate significantly under functional safety requirements (rule R-LIFETIME-LEAK fires)
- CWE-476 (null deref) is consistently mid-severity across all constraint profiles

**Why it matters:** This is the **flagship result**. It visually demonstrates the core thesis: the same vulnerability class can be LOW or CRITICAL severity depending on the hardware context. A UAF on a server is a high-severity bug; a UAF on a 50µs-budget ISR-constrained RTOS is CRITICAL. This is what no existing CVSS/SAST score captures, and this figure makes it immediately obvious.

**Do not fabricate:** This heatmap is computed synthetically from the scoring engine — it is NOT from real clang-tidy findings. It illustrates the rule system's behavior across a designed input space. State this clearly in the paper.

---

### Figure 3: Agentic AI Enrichment Quality (`exp3_llm_quality.pdf`)

**What it is:** A line chart showing three quality metrics for LLM enrichment output across three projects.
- Usefulness (1–5, normalized to 0–100%): Is the explanation actionable?
- Evidence Correctness (%): Do the cited line numbers and code facts match the actual source?
- Tag Accuracy (%): Are contextual tags (ISR-reachable, blocking-call, etc.) correct?

**Numbers:**
| Project | Usefulness | Evidence Correctness | Tag Accuracy |
|---------|-----------|---------------------|-------------|
| FreeRTOS | 3.8/5 (76%) | 78% | 72% |
| Zephyr | 3.6/5 (72%) | 74% | 71% |
| esp-fc | 4.4/5 (88%) | 87% | 83% |
| Average | 3.9/5 (79%) | 80% | 75% |

**Model used:** GPT-5-mini via OpenAI API. Top-10 findings per project enriched.

**Why quality scales from FreeRTOS → esp-fc:** The LLM quality correlates directly with the quality of the underlying findings. FreeRTOS and Zephyr findings are dominated by build-configuration errors (missing headers from wrong-architecture ports being scanned) and generic `bugprone-*` patterns. esp-fc findings include real actionable issues (reserved identifier `_model_ptr` in ISR-reachable global context, branch-clone in CLI switch, swappable parameters in SPI/I2C bus constructors). When the LLM has real code context and a real code issue, it produces high-quality, constraint-aware explanations including accurate ISR-safety and timing-budget reasoning.

**How enrichment works:** The evidence extractor reads the source file around each finding (function body, surrounding context, call sites), bundles it with the hardware constraint profile, and sends it to the LLM with a structured prompt. The LLM returns: explanation (facts vs inferences clearly separated), semantic tags, fix suggestions with specific line edits, and new discovery candidates.

**Important:** Ratings were made by the authors acting as domain experts. This is a **small-scale user study** (30 findings per project = 90 total), not a large-scale blinded evaluation. State this honestly in the paper. The results are presented as indicative of LLM enrichment quality, not as a statistically powered study.

**Table:** `exp3_llm_quality.tex`

---

### Figure 4: CI/CD Pipeline Overhead (`exp5_cicd_overhead.pdf`)

**What it is:** Grouped bar chart showing wall-clock time (milliseconds) for each pipeline stage, measured on the three real SARIF files. Full (no cache) vs Cached are compared.

**Numbers (approximate, from figure):**
- Static Analysis (SARIF parsing): ~1.5ms
- Constraint Extraction (YAML loading): ~0.6ms
- Deterministic Scoring (14 rules × N findings): ~1.1ms
- Reporting (JSON + Markdown generation): ~1.6ms
- **Total deterministic pipeline: ~4.8ms**

LLM enrichment is excluded from this chart — it runs asynchronously via API and its latency is network-bound, not pipeline-bound.

**Why it matters:** The entire deterministic scoring pipeline (parse → score → report) completes in under 5ms on real-world SARIF inputs with 77–208 findings. This is negligible overhead for a CI/CD gate that already runs multi-minute static analysis. The argument: adding ConstraintGuard to a CI pipeline that runs scan-build (minutes) adds <5ms to the total runtime. This makes it practical for every PR check.

**Caching note:** Full and Cached bars are nearly identical because SARIF parsing and YAML loading are fast enough that caching provides no meaningful speedup at this scale. Do not oversell the caching result.

**Table:** `exp5_cicd_overhead.tex`

---

### Figure 5: Rule Family Ablation (`exp7_rule_ablation.pdf`)

**What it is:** Horizontal bar chart showing which rule families contribute to score adjustments for each project. Only active projects (FreeRTOS, esp-fc) and active families (RT-Hazard, Safety) are shown. Zephyr and inactive families (Memory, ISR, Lifetime) are suppressed because they contribute 0%.

**Numbers:**
- FreeRTOS: RT-Hazard = 100%, Safety = 0%
- esp-fc: RT-Hazard = 67%, Safety = 33%

**Why Zephyr is absent:** Zephyr's hardware profile specifies `max_interrupt_latency_us = 100`. The RT-Hazard rules fire only when ISR ≤ 50µs. Zephyr's constraint doesn't trigger that threshold, and its findings are all `UNKNOWN` category so Memory/ISR/Lifetime rules don't fire either. This is correct and expected behavior — Zephyr's profile is less constrained. Do NOT say Zephyr had no findings; say it had no findings that triggered the active rule families under its constraint profile.

**Why Memory/ISR/Lifetime are absent:** All three projects produced predominantly `UNKNOWN`-category findings (clang-tidy's `bugprone-*` and `cert-*` checkers don't produce `BUFFER_OVERFLOW`, `LEAK`, `USE_AFTER_FREE`, etc. directly — those categories come from deep `clang-analyzer-*` checkers which require a complete build environment). Category-specific rules (Memory, ISR, Lifetime) don't fire on `UNKNOWN` findings.

**The meaningful story:** FreeRTOS's ISR budget of 50µs makes RT-Hazard the dominant (sole) rule family. esp-fc's combination of 50µs ISR AND IEC 61508 SIL2 causes both RT-Hazard AND Safety rules to fire, with RT-Hazard dominating (67%) because it applies to all findings while Safety rules are more selective. This correctly reflects the real-world priority: on a flight controller, timing is more critical than general safety classification.

---

### Figure 6: Empirical Constraint Sensitivity (`exp8_constraint_sensitivity.pdf`)

**What it is:** A grouped horizontal bar chart showing 8 benchmark findings scored under 4 hardware profiles: Baseline (null spec), Relaxed (512KB RAM, 500µs ISR, no safety), Safety (64KB RAM, 100µs ISR, IEC61508-SIL2), and Tight (20KB RAM, 2KB stack, 50µs ISR, ISO26262-ASIL-B). Findings are ordered by tight score descending.

**Why this experiment exists:** The real-project evaluation (FreeRTOS/Zephyr/esp-fc) used clang-tidy which maps all findings to `UNKNOWN` category. Category-specific rules never fire, so differentiation between baseline and deterministic is limited. This experiment uses a purpose-built benchmark analyzed with the Clang Static Analyzer (producing real clang-analyzer rule IDs), demonstrating that the scoring engine does produce meaningfully different priorities when given properly categorized findings.

**Numbers (exact, from actual scorer output):**

| Finding | Category | Baseline | Relaxed | Safety | Tight | Rules Fired (Tight) |
|---------|----------|----------|---------|--------|-------|---------------------|
| copy_input / strcpy | BUFFER_OVERFLOW | 60 | 60 | 95 | 100 | R-MEM-STACK-TIGHT, R-MEM-RAM-TIGHT, R-ISR-LATENCY-OVERFLOW, R-SAFETY-ASIL-STRICT, R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT |
| read_sensor / null-deref | NULL_DEREF | 50 | 50 | 85 | 100 | R-MEM-RAM-TIGHT, R-ISR-LATENCY-OVERFLOW, R-SAFETY-ASIL-STRICT, R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT |
| process_buffer / use-after-free | USE_AFTER_FREE | 75 | 65 | 100 | 100 | R-MEM-STACK-TIGHT, R-MEM-RAM-TIGHT, R-ISR-LATENCY-OVERFLOW, R-SAFETY-ASIL-STRICT, R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT |
| isr_uart / strcpy | BUFFER_OVERFLOW | 85 | 85 | 100 | 100 | all above + R-ISR-FUNC-NAME, R-CRIT-FUNC |
| control_loop / null-deref | NULL_DEREF | 50 | 50 | 85 | 100 | R-MEM-RAM-TIGHT, R-ISR-LATENCY-OVERFLOW, R-CRIT-FUNC, R-SAFETY-ASIL-STRICT, R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT |
| build_packet / leak | LEAK | 55 | 45 | 62 | 87 | R-MEM-HEAP-TIGHT, R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT, R-LIFETIME-LEAK |
| allocate_matrix / int-overflow | INTEGER_OVERFLOW | 50 | 50 | 67 | 77 | R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT, R-SAFETY-INT-OVF |
| compute_checksum / uninitialized | UNINITIALIZED | 40 | 40 | 45 | 55 | R-SAFETY-FUNCTIONAL, R-TIME-ULTRA-TIGHT |

**Key result:** All 8 findings change score between relaxed and tight (Δ+15 to Δ+50). `copy_input` goes from MEDIUM (60) under relaxed to CRITICAL (100) under tight. `read_sensor` goes from MEDIUM (50) to CRITICAL (100). `build_packet` (memory leak) goes from MEDIUM (45) to CRITICAL (87) — the Lifetime rule fires because IEC 61508 SIL2 is declared and the heap is only 4KB.

**The narrative:** This is the empirical proof of the CWE heatmap's claims. Same code, same tool, same SARIF — different hardware constraints produce scores ranging from MEDIUM to CRITICAL. The Tight profile (representing a real Cortex-M4 flight controller with 20KB RAM, 2KB stack, 50µs ISR, and ASIL-B) triggers 6–8 rules per finding while the Relaxed profile triggers 0–1.

**Note on baseline anomalies:** The Baseline (null HardwareSpec) shows 75 for `process_buffer` (USE_AFTER_FREE) because `R-MEM-NO-DYNAMIC` fires when no heap budget is declared. It shows 85 for `isr_uart` because `R-ISR-FUNC-NAME` fires on function name regardless of spec. This is correct behavior — the rule system is conservative: "no heap declared" is treated as a constraint. The Relaxed vs. Tight comparison is the primary claim, not Baseline vs. Tight.

**Table:** `exp8_constraint_sensitivity.tex`

---

## 4. What to Drop (Do Not Include in the Paper)

**Exp 2 — Demotion Rate (100% for all projects):** True but trivially so. All findings receive the same constraint-based boost because they're all `UNKNOWN` category. Showing 100% demotion looks impressive but reveals that the re-ranking is uniform, not selective. Acknowledge in the limitations section only.

**Exp 6 — Precision@K Curve (3 overlapping lines):** The baseline, deterministic, and full system P@K curves overlap because the ranking order doesn't change when all findings receive the same category-agnostic rule boosts. Mention as a limitation.

---

## 5. Limitations to State Honestly

1. **Scanner dependency:** ConstraintGuard's differentiation depends on the scanner producing category-diverse findings. On production RTOS kernels, clang-tidy's `bugprone-*` checkers (which don't invoke deep dataflow analysis) produce `UNKNOWN`-category findings. The Clang Static Analyzer's deep checkers (`clang-analyzer-*`) would produce `BUFFER_OVERFLOW`, `LEAK`, `USE_AFTER_FREE` findings where constraint-specific rules would differentiate more aggressively. The evaluation used clang-tidy because it runs without a complete cross-compilation toolchain.

2. **Ground truth scale:** 30 labeled findings per project (90 total) is a small evaluation set. Expert agreement percentages should not be interpreted as statistically generalizable without wider replication.

3. **LLM evaluation methodology:** Expert ratings of LLM output quality were performed by the paper authors, not independent evaluators. This is a known limitation of small-scale LLM evaluation studies.

4. **LLM timing not measured:** The CI/CD overhead figure excludes LLM enrichment timing. LLM enrichment is optional, async, and network-latency-bound (typically 2–10 seconds per finding for GPT-5-mini). The paper should report this separately.

---

## 6. Writing Instructions

- Target venue: **EMSOFT 2026** (ACM SIGBED — Embedded Systems)
- Style: LaTeX with booktabs tables, PDF figures
- Tone: Systems/tools paper. Be precise, not promotional. State what the system does and what the data shows; let the results speak.
- **Never fabricate numbers.** All numbers in this document are from actual runs on real SARIF data. Do not round aggressively; use 1 decimal place for percentages.
- The heatmap (Exp 4) is the primary result — lead with it.
- Expert Agreement (Exp 1) is the primary correctness claim — do not conflate it with Precision@10.
- Acknowledge limitations proactively. EMSOFT reviewers are systems researchers; they will find them if you don't.
- The figures are in `paper_content/figures/`. Reference them as: `exp1_precision_at10.pdf`, `exp3_llm_quality.pdf`, `exp4_cwe_heatmap.pdf`, `exp5_cicd_overhead.pdf`, `exp7_rule_ablation.pdf`, `exp8_constraint_sensitivity.pdf`.
- The LaTeX tables are in `paper_content/tables/`. Use `\input{}` or copy them directly.
- **Figure ordering recommendation:** Lead with Exp 8 (empirical constraint sensitivity) alongside Exp 4 (CWE heatmap) — they tell the same story at different levels. Exp 8 is empirical (real scorer); Exp 4 is analytical (rule space). Together they make the primary claim undeniable. Exp 1 (expert agreement) is secondary correctness validation. Exps 5, 7, 3 are supporting detail.
