# ConstraintGuard Risk Report

**Tool:** ConstraintGuard 0.1.0  
**Generated:** 2026-02-25 17:47:20 UTC  
**Config:** examples/configs/tight.yml  

```
constraintguard score --sarif examples/vuln_demo/findings.sarif --config examples/configs/tight.yml --out examples --top-k 10
```

---

## Constraint Profile

- **Platform:** cortex-m4  
- **Safety Level:** ISO26262-ASIL-B  
- **Memory:** RAM: 20KB   Flash: 256KB   Stack: 2KB   Heap: 4KB  
- **Max IRQ Latency:** 50µs  
- **Critical Functions:** `control_loop`, `isr_uart`, `watchdog_feed`  
- **Constraint Sources:** examples/configs/tight.yml  

---

## Severity Distribution

| Tier | Count |
|:-----|------:|
| CRITICAL | 5 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| **Total** | **8** |

---

## Findings

### [1] CRITICAL — score: 100 — `buffer_overflow`

**Location:** `examples/vuln_demo/main.c:15` in `copy_input`  
**Rule:** `security.insecureAPI.strcpy`  **CWE:** CWE-120  

**Why it's risky on this target:**  
A buffer overflow was detected in function 'copy_input' (examples/vuln_demo/main.c:15). On your cortex-m4 / ISO26262-ASIL-B target, this corrupts adjacent memory, potentially overwriting stack frames, return addresses, or global state — on a resource-constrained embedded target, recovery may require a full device reset. This finding is escalated because: Stack is tightly constrained at 2048B (≤4096B); buffer_overflow can overwrite stack frames and corrupt return addresses; Total RAM is limited to 20480B (≤64KB); buffer_overflow corrupts a significant fraction of addressable memory on this device; Maximum interrupt latency budget is 50µs (≤100µs); a buffer_overflow in an interrupt-sensitive code path can cause a missed real-time deadline; Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; buffer_overflow directly violates ISO 26262 ASIL freedom-from-interference requirements; Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Replace unsafe memory operations with size-bounded equivalents (strncpy, snprintf, memcpy with explicit length). Validate all input lengths before copying into fixed-size buffers. On embedded targets, prefer statically-sized buffers with compile-time size assertions that enforce upper bounds. With only 2KB of stack on this target, overflows are more likely to silently corrupt adjacent frames; enable stack canaries (-fstack-protector-all) and MPU stack-guard regions if the hardware supports it.

**Fired rules:**  
- `R-MEM-STACK-TIGHT` (+20): Stack is tightly constrained at 2048B (≤4096B); buffer_overflow can overwrite stack frames and corrupt return addresses. — constraints: `stack_size_bytes`  
- `R-MEM-RAM-TIGHT` (+15): Total RAM is limited to 20480B (≤64KB); buffer_overflow corrupts a significant fraction of addressable memory on this device. — constraints: `ram_size_bytes`  
- `R-ISR-LATENCY-OVERFLOW` (+15): Maximum interrupt latency budget is 50µs (≤100µs); a buffer_overflow in an interrupt-sensitive code path can cause a missed real-time deadline. — constraints: `max_interrupt_latency_us`  
- `R-SAFETY-ASIL-STRICT` (+15): Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; buffer_overflow directly violates ISO 26262 ASIL freedom-from-interference requirements. — constraints: `safety_level`  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

### [2] CRITICAL — score: 100 — `null_deref`

**Location:** `examples/vuln_demo/main.c:22` in `read_sensor`  
**Rule:** `core.NullDereference`  **CWE:** CWE-476  

**Why it's risky on this target:**  
A null pointer dereference was detected in function 'read_sensor' (examples/vuln_demo/main.c:22). On your cortex-m4 / ISO26262-ASIL-B target, this triggers a processor fault (e.g., ARM HardFault) that halts execution immediately — on bare-metal or RTOS targets there is typically no OS-level exception handler to recover from this. This finding is escalated because: Total RAM is limited to 20480B (≤64KB); null_deref corrupts a significant fraction of addressable memory on this device; Maximum interrupt latency budget is 50µs (≤100µs); a null_deref in an interrupt-sensitive code path can cause a missed real-time deadline; Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; null_deref directly violates ISO 26262 ASIL freedom-from-interference requirements; Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Add null-pointer guards before every pointer dereference. Use assertion macros in debug builds and explicit error-return paths in production. On bare-metal targets, a null dereference typically triggers a HardFault — ensure a fault handler is installed that logs diagnostics and performs a controlled reset. In safety-critical functions, add both a pre-condition null check and a static assertion to document and enforce the non-null invariant at compile time.

**Fired rules:**  
- `R-MEM-RAM-TIGHT` (+15): Total RAM is limited to 20480B (≤64KB); null_deref corrupts a significant fraction of addressable memory on this device. — constraints: `ram_size_bytes`  
- `R-ISR-LATENCY-OVERFLOW` (+15): Maximum interrupt latency budget is 50µs (≤100µs); a null_deref in an interrupt-sensitive code path can cause a missed real-time deadline. — constraints: `max_interrupt_latency_us`  
- `R-SAFETY-ASIL-STRICT` (+15): Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; null_deref directly violates ISO 26262 ASIL freedom-from-interference requirements. — constraints: `safety_level`  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

### [3] CRITICAL — score: 100 — `use_after_free`

**Location:** `examples/vuln_demo/main.c:52` in `process_buffer`  
**Rule:** `unix.Malloc`  **CWE:** CWE-401  

**Why it's risky on this target:**  
A use-after-free was detected in function 'process_buffer' (examples/vuln_demo/main.c:52). On your cortex-m4 / ISO26262-ASIL-B target, this accesses freed memory that may have been reallocated, introducing non-deterministic behaviour — on embedded targets without full memory protection, this can silently corrupt live data structures. This finding is escalated because: Stack is tightly constrained at 2048B (≤4096B); use_after_free can overwrite stack frames and corrupt return addresses; Total RAM is limited to 20480B (≤64KB); use_after_free corrupts a significant fraction of addressable memory on this device; Maximum interrupt latency budget is 50µs (≤100µs); a use_after_free in an interrupt-sensitive code path can cause a missed real-time deadline; Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; use_after_free directly violates ISO 26262 ASIL freedom-from-interference requirements; Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Set pointers to NULL immediately after freeing. Audit all pointer copies and lifetime boundaries; prefer single-owner allocation patterns. On embedded firmware, apply MPU read-after-free detection during testing if the hardware supports memory protection. With only 2KB of stack on this target, overflows are more likely to silently corrupt adjacent frames; enable stack canaries (-fstack-protector-all) and MPU stack-guard regions if the hardware supports it.

**Fired rules:**  
- `R-MEM-STACK-TIGHT` (+20): Stack is tightly constrained at 2048B (≤4096B); use_after_free can overwrite stack frames and corrupt return addresses. — constraints: `stack_size_bytes`  
- `R-MEM-RAM-TIGHT` (+15): Total RAM is limited to 20480B (≤64KB); use_after_free corrupts a significant fraction of addressable memory on this device. — constraints: `ram_size_bytes`  
- `R-ISR-LATENCY-OVERFLOW` (+15): Maximum interrupt latency budget is 50µs (≤100µs); a use_after_free in an interrupt-sensitive code path can cause a missed real-time deadline. — constraints: `max_interrupt_latency_us`  
- `R-SAFETY-ASIL-STRICT` (+15): Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; use_after_free directly violates ISO 26262 ASIL freedom-from-interference requirements. — constraints: `safety_level`  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

### [4] CRITICAL — score: 100 — `buffer_overflow`

**Location:** `examples/vuln_demo/main.c:76` in `isr_uart`  
**Rule:** `security.insecureAPI.strcpy`  **CWE:** CWE-120  

**Why it's risky on this target:**  
A buffer overflow was detected in function 'isr_uart' (examples/vuln_demo/main.c:76). On your cortex-m4 / ISO26262-ASIL-B target, this corrupts adjacent memory, potentially overwriting stack frames, return addresses, or global state — on a resource-constrained embedded target, recovery may require a full device reset. This finding is escalated because: Stack is tightly constrained at 2048B (≤4096B); buffer_overflow can overwrite stack frames and corrupt return addresses; Total RAM is limited to 20480B (≤64KB); buffer_overflow corrupts a significant fraction of addressable memory on this device; Function 'isr_uart' matches interrupt service routine naming conventions; a fault in an ISR cannot be caught by normal exception handling and may lock the device; Maximum interrupt latency budget is 50µs (≤100µs); a buffer_overflow in an interrupt-sensitive code path can cause a missed real-time deadline; Function 'isr_uart' is designated safety-critical in the constraint profile; any defect in this function directly impacts controlled system operation; Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; buffer_overflow directly violates ISO 26262 ASIL freedom-from-interference requirements; Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Replace unsafe memory operations with size-bounded equivalents (strncpy, snprintf, memcpy with explicit length). Validate all input lengths before copying into fixed-size buffers. On embedded targets, prefer statically-sized buffers with compile-time size assertions that enforce upper bounds. With only 2KB of stack on this target, overflows are more likely to silently corrupt adjacent frames; enable stack canaries (-fstack-protector-all) and MPU stack-guard regions if the hardware supports it.

**Fired rules:**  
- `R-MEM-STACK-TIGHT` (+20): Stack is tightly constrained at 2048B (≤4096B); buffer_overflow can overwrite stack frames and corrupt return addresses. — constraints: `stack_size_bytes`  
- `R-MEM-RAM-TIGHT` (+15): Total RAM is limited to 20480B (≤64KB); buffer_overflow corrupts a significant fraction of addressable memory on this device. — constraints: `ram_size_bytes`  
- `R-ISR-FUNC-NAME` (+25): Function 'isr_uart' matches interrupt service routine naming conventions; a fault in an ISR cannot be caught by normal exception handling and may lock the device. — constraints: `function`  
- `R-ISR-LATENCY-OVERFLOW` (+15): Maximum interrupt latency budget is 50µs (≤100µs); a buffer_overflow in an interrupt-sensitive code path can cause a missed real-time deadline. — constraints: `max_interrupt_latency_us`  
- `R-CRIT-FUNC` (+25): Function 'isr_uart' is designated safety-critical in the constraint profile; any defect in this function directly impacts controlled system operation. — constraints: `critical_functions`  
- `R-SAFETY-ASIL-STRICT` (+15): Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; buffer_overflow directly violates ISO 26262 ASIL freedom-from-interference requirements. — constraints: `safety_level`  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

### [5] CRITICAL — score: 100 — `null_deref`

**Location:** `examples/vuln_demo/main.c:83` in `control_loop`  
**Rule:** `core.NullDereference`  **CWE:** CWE-476  

**Why it's risky on this target:**  
A null pointer dereference was detected in function 'control_loop' (examples/vuln_demo/main.c:83). On your cortex-m4 / ISO26262-ASIL-B target, this triggers a processor fault (e.g., ARM HardFault) that halts execution immediately — on bare-metal or RTOS targets there is typically no OS-level exception handler to recover from this. This finding is escalated because: Total RAM is limited to 20480B (≤64KB); null_deref corrupts a significant fraction of addressable memory on this device; Maximum interrupt latency budget is 50µs (≤100µs); a null_deref in an interrupt-sensitive code path can cause a missed real-time deadline; Function 'control_loop' is designated safety-critical in the constraint profile; any defect in this function directly impacts controlled system operation; Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; null_deref directly violates ISO 26262 ASIL freedom-from-interference requirements; Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Add null-pointer guards before every pointer dereference. Use assertion macros in debug builds and explicit error-return paths in production. On bare-metal targets, a null dereference typically triggers a HardFault — ensure a fault handler is installed that logs diagnostics and performs a controlled reset. In safety-critical functions, add both a pre-condition null check and a static assertion to document and enforce the non-null invariant at compile time.

**Fired rules:**  
- `R-MEM-RAM-TIGHT` (+15): Total RAM is limited to 20480B (≤64KB); null_deref corrupts a significant fraction of addressable memory on this device. — constraints: `ram_size_bytes`  
- `R-ISR-LATENCY-OVERFLOW` (+15): Maximum interrupt latency budget is 50µs (≤100µs); a null_deref in an interrupt-sensitive code path can cause a missed real-time deadline. — constraints: `max_interrupt_latency_us`  
- `R-CRIT-FUNC` (+25): Function 'control_loop' is designated safety-critical in the constraint profile; any defect in this function directly impacts controlled system operation. — constraints: `critical_functions`  
- `R-SAFETY-ASIL-STRICT` (+15): Safety integrity level 'ISO26262-ASIL-B' mandates deterministic memory-safe behaviour; null_deref directly violates ISO 26262 ASIL freedom-from-interference requirements. — constraints: `safety_level`  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

### [6] HIGH — score: 77 — `integer_overflow`

**Location:** `examples/vuln_demo/main.c:58` in `allocate_matrix`  
**Rule:** `alpha.core.CastSize`  **CWE:** CWE-190  

**Why it's risky on this target:**  
A integer overflow was detected in function 'allocate_matrix' (examples/vuln_demo/main.c:58). On your cortex-m4 / ISO26262-ASIL-B target, this silently wraps arithmetic results, producing incorrect values that propagate through control, sensor, or actuator calculations without any runtime indication. This finding is escalated because: Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack; and Safety standard 'ISO26262-ASIL-B' is active; integer overflow can silently produce incorrect sensor or actuator values, violating numerical safety invariants.

**Remediation:**  
Validate arithmetic operands against their type bounds before computation. Enable UBSan (undefined behaviour sanitizer) during testing. In safety-critical paths, use checked-arithmetic macros or a safe-integer library that returns an error on overflow instead of wrapping silently. Under ISO26262-ASIL-B, apply a MISRA-compliant checked-arithmetic pattern for every arithmetic operation in the call path of this finding.

**Fired rules:**  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  
- `R-SAFETY-INT-OVF` (+12): Safety standard 'ISO26262-ASIL-B' is active; integer overflow can silently produce incorrect sensor or actuator values, violating numerical safety invariants. — constraints: `safety_level`  

---

### [7] HIGH — score: 75 — `leak`

**Location:** `examples/vuln_demo/main.c:35` in `build_packet`  
**Rule:** `unix.Malloc`  **CWE:** CWE-401  

**Why it's risky on this target:**  
A memory leak was detected in function 'build_packet' (examples/vuln_demo/main.c:35). On your cortex-m4 / ISO26262-ASIL-B target, this permanently consumes heap or pool memory on each call path that reaches it — on embedded targets with kilobytes of RAM, repeated leaks exhaust available memory rapidly. This finding is escalated because: Heap budget is only 4096B (≤8192B); repeated memory leaks rapidly exhaust the allocation pool and trigger undefined behaviour; Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Ensure every allocation has a corresponding free on all exit paths, including error paths. On embedded targets, consider replacing dynamic allocation with a static memory pool or arena allocator, which eliminates fragmentation and removes leak risk entirely. MISRA C Rule 21.3 prohibits dynamic memory allocation in safety-critical code. With only 4KB of heap on this target, a single recurring leak path will exhaust memory quickly; replacing all dynamic allocation with a fixed-size pool allocator is strongly recommended.

**Fired rules:**  
- `R-MEM-HEAP-TIGHT` (+15): Heap budget is only 4096B (≤8192B); repeated memory leaks rapidly exhaust the allocation pool and trigger undefined behaviour. — constraints: `heap_size_bytes`  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

### [8] MEDIUM — score: 55 — `uninitialized`

**Location:** `examples/vuln_demo/main.c:69` in `compute_checksum`  
**Rule:** `core.uninitialized.UndefReturn`  **CWE:** CWE-457  

**Why it's risky on this target:**  
A uninitialized memory read was detected in function 'compute_checksum' (examples/vuln_demo/main.c:69). On your cortex-m4 / ISO26262-ASIL-B target, this reads indeterminate stack or register values, producing device-specific non-deterministic behaviour that is difficult to reproduce and may differ between debug and release builds. This finding is escalated because: Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria; and Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack.

**Remediation:**  
Initialize all variables at the point of declaration. Enable -Wuninitialized and -Wmaybe-uninitialized compiler warnings and treat them as errors. In safety-critical code, zero-initialize all buffers and structs explicitly and avoid relying on BSS initialization order across translation units. Under ISO26262-ASIL-B, treat uninitialized reads as non-compliant by default and require zero-initialization of all local variables in safety-relevant translation units.

**Fired rules:**  
- `R-SAFETY-FUNCTIONAL` (+5): Functional safety standard 'ISO26262-ASIL-B' is declared for this target; all findings are escalated to reflect stricter acceptance criteria. — constraints: `safety_level`  
- `R-TIME-ULTRA-TIGHT` (+10): Interrupt latency budget is extremely tight at 50µs (≤50µs); findings across any execution path are escalated due to near-zero timing slack. — constraints: `max_interrupt_latency_us`  

---

> Full structured details (scores, rule traces, provenance): [report.json](report.json)
