# SARIF Acquisition for ConstraintGuard Evaluation

Each subdirectory contains a `Dockerfile` and `run_scan.sh` that:
1. Clone the target repo at a pinned commit (reproducible)
2. Install the required toolchain inside Docker
3. Run Clang Static Analyzer to produce SARIF
4. Place the output at `eval/data/sarif/<project>/findings.sarif`

## Prerequisites

- Docker (tested with Docker 24+)
- ~10GB free disk space (Zephyr SDK is ~2GB)

## Quick Start

```bash
# Run all three projects (sequential):
bash eval/sarif_acquisition/freertos/run_scan.sh
bash eval/sarif_acquisition/zephyr/run_scan.sh
bash eval/sarif_acquisition/espfc/run_scan.sh
```

## Individual Project Notes

### FreeRTOS
- Builds the GCC/ARM_CM3 portable layer
- Uses `-fsyntax-only` — no ARM linker required
- Expected findings: 15-40 (mostly memory safety)

### Zephyr
- Builds `samples/hello_world` for ESP32 board
- Requires Zephyr SDK (downloaded in Dockerfile, ~2GB)
- Expected findings: 20-60 (ISR patterns + memory)

### esp-fc
- Builds with PlatformIO + ESP-IDF framework
- Expected findings: 30-80 (safety-critical patterns)

## SARIF Format Notes

Clang outputs HTML from `scan-build`. The scripts convert this to SARIF 2.1.0
using `clang-tidy`'s `--export-fixes` with SARIF output, or by running
`clang` with `-analyze -Xclang -analyzer-output=sarif`.

If the target does not compile cleanly with Clang (common for ESP32/Xtensa),
`run_scan.sh` falls back to running `clang-tidy` per-file with the
`--export-fixes` format converted to SARIF by a bundled Python converter.
