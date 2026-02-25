# ConstraintGuard Risk Report

**Tool:** ConstraintGuard 0.1.0  
**Generated:** 2026-02-25 17:05:40 UTC  
**Source:** examples/vuln_demo  
**Config:** examples/configs/tight.yml  

```
constraintguard run --source examples/vuln_demo --build-cmd 'make' --config examples/configs/tight.yml --out out/demo
```

---

## Constraint Profile

- **Platform:** cortex-m4  
- **Safety Level:** ISO26262-ASIL-B  
- **Memory:** RAM: 20KB   Flash: 256KB   Stack: 2KB   Heap: 4KB  
- **Max IRQ Latency:** 50µs  
- **Critical Functions:** `control_loop`, `isr_uart`  
- **Constraint Sources:** examples/configs/tight.yml, examples/vuln_demo/linker.ld  

---

## Severity Distribution

| Tier | Count |
|:-----|------:|
| CRITICAL | 2 |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| **Total** | **3** |

---

## Findings

### [1] CRITICAL — score: 92 — `null-dereference`

**Location:** `src/control.c:85` in `control_loop`  
**Rule:** `core.NullDereference`  **CWE:** CWE-476  

**Why it's risky on this target:**  
Null dereference in control_loop is critical: this is a marked critical function under ISO26262-ASIL-B with a 50us interrupt latency budget.

**Remediation:**  
Add null checks before dereferencing pointers in control_loop. Consider using defensive coding patterns required by ASIL-B.

**Fired rules:**  
- `critical-function-hit` (+25): Null dereference in critical function 'control_loop' — constraints: `critical_functions`  
- `safety-critical-context` (+8): Finding in safety-critical context (ISO26262-ASIL-B) — constraints: `safety_level`  
- `interrupt-latency-risk` (+4): Crash in control path may violate 50us interrupt latency budget — constraints: `max_interrupt_latency_us`  

---

### [2] CRITICAL — score: 88 — `stack-overflow`

**Location:** `src/comm.c:42` in `send_response`  
**Rule:** `core.StackAddressEscape`  **CWE:** CWE-562  

**Why it's risky on this target:**  
Stack address escape in send_response is critical under a 2KB stack budget. Safety context ISO26262-ASIL-B further escalates this finding.

**Remediation:**  
Avoid returning pointers to stack-allocated buffers. Use a caller-provided buffer or a statically allocated region.

**Fired rules:**  
- `mem-tight-stack-overflow` (+20): Stack overflow risk escalated: stack budget is 2048 bytes — constraints: `stack_size_bytes`  
- `safety-critical-context` (+8): Finding in safety-critical context (ISO26262-ASIL-B) — constraints: `safety_level`  

---

### [3] HIGH — score: 72 — `memory-leak`

**Location:** `src/sensor.c:118` in `read_sensor_data`  
**Rule:** `unix.Malloc`  **CWE:** CWE-401  

**Why it's risky on this target:**  
Memory leak in read_sensor_data is high-risk under a 4KB heap budget with only 20KB total RAM.

**Remediation:**  
Ensure all allocated memory is freed on every code path. Consider using a pool allocator sized to the heap budget.

**Fired rules:**  
- `mem-tight-heap-leak` (+15): Memory leak escalated: heap budget is 4096 bytes — constraints: `heap_size_bytes`  
- `ram-pressure` (+7): RAM is constrained to 20480 bytes; leaks exhaust available memory faster — constraints: `ram_size_bytes`  

---

> Full structured details (scores, rule traces, provenance): [report.json](report.json)
