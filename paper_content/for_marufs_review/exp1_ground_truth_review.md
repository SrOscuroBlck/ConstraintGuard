# ConstraintGuard — Ground Truth Label Review
## Expert Validation Sheet (Exp 1)

**Purpose:** We labeled 82 static analysis findings across three embedded projects as *critical* or *not critical*, relative to each project's hardware constraints. We are asking you to independently review our labels and mark any you disagree with.

**What "critical" means here:** A finding is *critical* if, in the context of that project's hardware constraints (RAM, stack, ISR latency, safety level), it could directly cause a timing failure, memory corruption, safety violation, or incorrect system behavior. Build-configuration artifacts (e.g., missing headers caused by scanning without a full toolchain) are always *not critical*.

**Instructions:** For each finding, our label and reasoning are shown. Please mark:
- ✅ **Agree** — you agree with the label
- ❌ **Disagree** — you would label it differently (write your reasoning)
- ❓ **Uncertain** — insufficient context to judge

---

## Project 1: FreeRTOS-Kernel
**Platform:** Cortex-M3 · 20 KB RAM · 2 KB stack · 50 µs max ISR latency
**Critical functions:** `vTaskSwitchContext`, `xQueueReceive`, `vPortYield`

| # | File & Line | Checker | Our Label | Reasoning | Your Rating |
|---|-------------|---------|-----------|-----------|-------------|
| 1 | `event_groups.c:313` | bugprone-easily-swappable-parameters | **CRITICAL** | `xEventGroupWaitBits`: swapping `uxBitsToWaitFor`/`uxBitsToSet` silently causes wrong event mask evaluation on a 50 µs ISR budget. | ✅ / ❌ / ❓ |
| 2 | `event_groups.c:779` | bugprone-easily-swappable-parameters | **CRITICAL** | Same function — `prvTestWaitCondition`: identical risk as above. | ✅ / ❌ / ❓ |
| 3 | `deprecated_definitions.h:161` | clang-diagnostic-error | not critical | Missing header — scanner artifact, not a real finding. | ✅ / ❌ / ❓ |
| 4 | `ARMv8M/.../ARM_CM33/portasm.c:39` | clang-diagnostic-error | not critical | Missing header from wrong-architecture port being scanned. | ✅ / ❌ / ❓ |
| 5 | `ARMv8M/.../ARM_CM33_NTZ/portasm.c:39` | clang-diagnostic-error | not critical | Same as above. | ✅ / ❌ / ❓ |
| 6 | `ARMv8M/.../ARM_CM33/secure_context_port.c:30` | clang-diagnostic-error | not critical | Missing header from wrong-architecture port being scanned. | ✅ / ❌ / ❓ |
| 7 | `GCC/ARM_CM33/non_secure/port.c:260` | bugprone-macro-parentheses | not critical | Macro parenthesization style issue — no runtime impact in this context. | ✅ / ❌ / ❓ |
| 8 | `GCC/ARM_CM33/secure/secure_heap.c:81` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 9 | `GCC/ARM_CM33/secure/secure_heap.c:82` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 10 | `GCC/ARM_CM33/secure/secure_heap.c:83` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 11 | `GCC/ARM_CM33_NTZ/non_secure/port.c:260` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 12 | `GCC/ARM_CM35P/non_secure/port.c:260` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 13 | `GCC/ARM_CM35P/secure/secure_heap.c:81` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 14 | `GCC/ARM_CM35P/secure/secure_heap.c:82` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 15 | `GCC/ARM_CM35P/secure/secure_heap.c:83` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 16 | `GCC/ARM_CM35P_NTZ/non_secure/port.c:260` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 17 | `GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c:845` | bugprone-easily-swappable-parameters | **CRITICAL** | MPU wrapper: swapping `uxIndexToWaitOn`/`xClearCountOnExit`/`xTicksToWait` silently passes wrong tick budget in 50 µs ISR context, corrupting task scheduling. | ✅ / ❌ / ❓ |
| 18 | `GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c:908` | bugprone-easily-swappable-parameters | **CRITICAL** | Same file — same MPU wrapper risk. | ✅ / ❌ / ❓ |
| 19 | `GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c:1214` | bugprone-easily-swappable-parameters | **CRITICAL** | Same file — same MPU wrapper risk. | ✅ / ❌ / ❓ |
| 20 | `GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c:1736` | bugprone-easily-swappable-parameters | **CRITICAL** | Same file — same MPU wrapper risk. | ✅ / ❌ / ❓ |
| 21 | `GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c:1830` | bugprone-easily-swappable-parameters | **CRITICAL** | Same file — same MPU wrapper risk. | ✅ / ❌ / ❓ |
| 22 | `GCC/ARM_CM3_MPU/mpu_wrappers_v2_asm.c:1865` | bugprone-easily-swappable-parameters | **CRITICAL** | Same file — same MPU wrapper risk. | ✅ / ❌ / ❓ |
| 23 | `GCC/ARM_CM3_MPU/port.c:135` | bugprone-macro-parentheses | not critical | Style issue only. | ✅ / ❌ / ❓ |
| 24 | `GCC/ARM_CM3_MPU/port.c:299` | bugprone-branch-clone | **CRITICAL** | Identical if/else branches in MPU privilege check — privilege escalation path is dead code, violating the MPU security invariant on Cortex-M3. | ✅ / ❌ / ❓ |
| 25 | `GCC/ARM_CM3_MPU/port.c:501` | bugprone-reserved-identifier | not critical | Linker-script symbol naming uses double-underscore convention by design. | ✅ / ❌ / ❓ |
| 26 | `GCC/ARM_CM3_MPU/port.c:502` | bugprone-reserved-identifier | not critical | Same as above. | ✅ / ❌ / ❓ |
| 27 | `GCC/ARM_CM3_MPU/port.c:565` | bugprone-branch-clone | **CRITICAL** | Same as #24 — dead privilege escalation path. | ✅ / ❌ / ❓ |
| 28 | `GCC/ARM_CM3_MPU/port.c:614` | bugprone-reserved-identifier | not critical | Linker-script symbol by design. | ✅ / ❌ / ❓ |
| 29 | `GCC/ARM_CM3_MPU/port.c:615` | bugprone-reserved-identifier | not critical | Linker-script symbol by design. | ✅ / ❌ / ❓ |
| 30 | `GCC/ARM_CM3_MPU/port.c:1116` | bugprone-reserved-identifier | not critical | Linker-script symbol by design. | ✅ / ❌ / ❓ |

**Our critical count: 10 / 30**

---

## Project 2: Zephyr RTOS
**Platform:** ESP32 · 520 KB RAM · 8 KB stack · 100 µs max ISR latency
**Critical functions:** `k_sleep`, `k_sem_take`, `k_thread_create`

| # | File & Line | Checker | Our Label | Reasoning | Your Rating |
|---|-------------|---------|-----------|-------------|-------------|
| 1 | `kernel_structs.h:209` | clang-diagnostic-error | not critical | `CONFIG_MP_MAX_NUM_CPUS` undefined — missing Kconfig, scanner artifact. | ✅ / ❌ / ❓ |
| 2 | `sys/atomic.h:42` | clang-diagnostic-error | not critical | `CONFIG_ATOMIC_OPERATIONS_*` undefined — Kconfig artifact. | ✅ / ❌ / ❓ |
| 3 | `sys/atomic.h:341` | clang-diagnostic-error | not critical | Conflicting types for `atomic_get` — result of scanning without generated headers. | ✅ / ❌ / ❓ |
| 4 | `sys/atomic.h:427` | clang-diagnostic-error | not critical | Conflicting types for `atomic_or` — same as above. | ✅ / ❌ / ❓ |
| 5 | `sys/atomic.h:457` | clang-diagnostic-error | not critical | Conflicting types for `atomic_and` — same as above. | ✅ / ❌ / ❓ |
| 6 | `sys/errno_private.h:54` | clang-diagnostic-error | not critical | Missing generated syscall header — scanner artifact. | ✅ / ❌ / ❓ |
| 7 | `syscall.h:11` | clang-diagnostic-error | not critical | Missing `syscall_list.h` — generated at build time, not present in source scan. | ✅ / ❌ / ❓ |
| 8 | `toolchain/gcc.h:614` | clang-diagnostic-error | not critical | `#error "processor architecture not supported"` — ESP32/Xtensa not detected without full Kconfig. | ✅ / ❌ / ❓ |
| 9 | `kernel/atomic_c.c:81` | bugprone-easily-swappable-parameters | **CRITICAL** | `z_impl_atomic_cas`: swapping `old`/`new` causes ABA race in kernel synchronization primitives. | ✅ / ❌ / ❓ |
| 10 | `kernel/atomic_c.c:118` | bugprone-easily-swappable-parameters | **CRITICAL** | `z_impl_atomic_ptr_cas`: same ABA race risk on pointer CAS. | ✅ / ❌ / ❓ |
| 11 | `kernel/compiler_stack_protect.c:36` | bugprone-reserved-identifier | not critical | Internal Zephyr symbol name — reserved identifier by design. | ✅ / ❌ / ❓ |
| 12 | `kernel/compiler_stack_protect.c:55` | bugprone-reserved-identifier | not critical | Same as above. | ✅ / ❌ / ❓ |
| 13 | `kernel/cpu_mask.c:19` | bugprone-easily-swappable-parameters | not critical | Low-priority under Zephyr's relaxed constraint profile (100 µs budget). | ✅ / ❌ / ❓ |
| 14 | `kernel/dynamic.c:34` | bugprone-easily-swappable-parameters | **CRITICAL** | Thread stack allocator: swapping `size`/`alignment` corrupts stack layout → silent stack overflow. | ✅ / ❌ / ❓ |
| 15 | `kernel/dynamic.c:59` | bugprone-easily-swappable-parameters | **CRITICAL** | Same function — same stack corruption risk. | ✅ / ❌ / ❓ |
| 16 | `kernel/dynamic_disabled.c:12` | bugprone-easily-swappable-parameters | **CRITICAL** | Stack allocator stub: same size/alignment swap risk. | ✅ / ❌ / ❓ |
| 17 | `kernel/errno.c:23` | bugprone-reserved-identifier | not critical | Internal Zephyr symbol by design. | ✅ / ❌ / ❓ |
| 18 | `kernel/events.c:95` | bugprone-easily-swappable-parameters | not critical | Low-priority under relaxed Zephyr constraint profile. | ✅ / ❌ / ❓ |
| 19 | `kernel/events.c:282` | bugprone-easily-swappable-parameters | not critical | Low-priority under relaxed Zephyr constraint profile. | ✅ / ❌ / ❓ |
| 20 | `kernel/futex.c:56` | bugprone-narrowing-conversions | not critical | Known narrowing pattern in futex — not exploitable at 520 KB RAM scale. | ✅ / ❌ / ❓ |
| 21 | `kernel/futex.c:67` | bugprone-suspicious-include | **CRITICAL** | `#include` of a `.c` file → ODR violation → undefined behavior at link time in the kernel synchronization path. | ✅ / ❌ / ❓ |
| 22 | `kernel/futex.c:105` | bugprone-suspicious-include | **CRITICAL** | Same `.c` include issue — same ODR risk. | ✅ / ❌ / ❓ |
| 23 | `kernel/include/offsets_short.h:10` | clang-diagnostic-error | not critical | Missing generated offsets header — scanner artifact. | ✅ / ❌ / ❓ |
| 24 | `kernel/init.c:118` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |
| 25 | `kernel/init.c:119` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |
| 26 | `kernel/init.c:120` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |
| 27 | `kernel/init.c:121` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |
| 28 | `kernel/init.c:122` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |
| 29 | `kernel/init.c:123` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |
| 30 | `kernel/init.c:124` | bugprone-reserved-identifier | not critical | Linker symbol by design. | ✅ / ❌ / ❓ |

**Our critical count: 7 / 30**

---

## Project 3: esp-fc (Flight Controller)
**Platform:** ESP32 · 192 KB RAM · 8 KB stack · 50 µs max ISR latency · **IEC 61508 SIL2**
**Critical functions:** `handle_isr`, `pid_controller`, `motor_control`, `imu_read`

| # | File & Line | Checker | Our Label | Reasoning | Your Rating |
|---|-------------|---------|-----------|-----------|-------------|
| 1 | `Blackbox/BlackboxBridge.cpp:3` | bugprone-reserved-identifier | not critical | Reserved identifier `_model_ptr` — UB risk but not flight-critical path. | ✅ / ❌ / ❓ |
| 2 | `Input.cpp:17` | bugprone-narrowing-conversions | **CRITICAL** | `int→float` narrowing in RC input parsing: control surface commands off by up to 1 LSB → SIL2 numerical accuracy requirement violated. | ✅ / ❌ / ❓ |
| 3 | `Input.cpp:24` | bugprone-narrowing-conversions | **CRITICAL** | Same file — same narrowing in RC input, same SIL2 violation. | ✅ / ❌ / ❓ |
| 4 | `Wireless.cpp:58` | bugprone-easily-swappable-parameters | not critical | WiFi event handler — parameter swap affects telemetry only, not flight-critical path. | ✅ / ❌ / ❓ |
| 5 | `Hardware.cpp:35` | cert-err58-cpp | not critical | Static initializer exception risk — acceptable in embedded init context. | ✅ / ❌ / ❓ |
| 6 | `SerialManager.cpp:7` | bugprone-reserved-identifier | not critical | UART hardware register names — reserved by platform convention. | ✅ / ❌ / ❓ |
| 7 | `SerialManager.cpp:11` | bugprone-reserved-identifier | not critical | Same as above. | ✅ / ❌ / ❓ |
| 8 | `SerialManager.cpp:15` | bugprone-reserved-identifier | not critical | Same as above. | ✅ / ❌ / ❓ |
| 9 | `SerialManager.cpp:57` | bugprone-implicit-widening-of-multiplication-result | **CRITICAL** | Buffer size calculation may overflow 16-bit type → buffer overrun in serial DMA path. | ✅ / ❌ / ❓ |
| 10 | `Blackbox/BlackboxFlashfs.cpp:1` | clang-diagnostic-error | not critical | Missing Arduino.h — scanner artifact (PlatformIO toolchain not present). | ✅ / ❌ / ❓ |
| 11 | `Debug_Espfc.h:4` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 12 | `Device/MagDevice.h:3` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 13 | `Device/BusSPI.cpp:16` | bugprone-easily-swappable-parameters | **CRITICAL** | SPI `begin()`: swapping SCK/MISO/MOSI pin params misconfigures IMU bus → gyro data lost → flight controller instability. IEC 61508 SIL2 violation. | ✅ / ❌ / ❓ |
| 14 | `Device/BusSPI.cpp:29` | bugprone-narrowing-conversions | not critical | Low-priority narrowing in SPI, not on critical path. | ✅ / ❌ / ❓ |
| 15 | `Target/TargetEsp32Common.h:3` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 16 | `Device/BusI2C.cpp:15` | bugprone-easily-swappable-parameters | **CRITICAL** | I2C `begin()`: swapping SDA/SCL pin params → all I2C sensors (baro, magnetometer) lost. IEC 61508 SIL2 violation. | ✅ / ❌ / ❓ |
| 17 | `Device/BusSlave.cpp:1` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 18 | `Device/BusSlave.cpp:26` | bugprone-easily-swappable-parameters | **CRITICAL** | Slave bus `read()`: swapping address/length reads wrong sensor register → corrupted IMU readings passed to PID controller in 50 µs ISR. | ✅ / ❌ / ❓ |
| 19 | `Hal/Pgm.h:5` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 20 | `Device/SerialDevice.h:5` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 21 | `Device/InputEspNow.h:6` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |
| 22 | `Device/GyroDevice.h:3` | clang-diagnostic-error | not critical | Missing SDK header — scanner artifact. | ✅ / ❌ / ❓ |

**Our critical count: 6 / 22**

---

## Summary of Our Labels

| Project | Total Findings Reviewed | Critical | Not Critical |
|---------|------------------------|----------|--------------|
| FreeRTOS | 30 | 10 | 20 |
| Zephyr | 30 | 7 | 23 |
| esp-fc | 22 | 6 | 16 |
| **Total** | **82** | **23** | **59** |

---

*Thank you for your review. Please return this sheet with your ratings filled in. Any disagreements or comments are valuable — the goal is to have two independent expert opinions on the ground truth labels.*
