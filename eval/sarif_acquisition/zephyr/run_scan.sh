#!/usr/bin/env bash
# Scan Zephyr RTOS kernel with clang-tidy (no build system needed).
#
# Usage (Docker):
#   docker build -t cg-scan-zephyr -f eval/sarif_acquisition/zephyr/Dockerfile eval/sarif_acquisition/
#   docker run --rm \
#     -v "$(pwd)/eval/data/sarif/zephyr:/output" \
#     -e CONSTRAINTGUARD_LLM_API_KEY \
#     -e CONSTRAINTGUARD_LLM_MODEL \
#     -e CONSTRAINTGUARD_LLM_PROVIDER \
#     cg-scan-zephyr
#
# Without LLM env vars the scan still runs; discoveries.json will be empty.

set -euo pipefail

ZEPHYR_ROOT="${ZEPHYR_ROOT:-/src/zephyr}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
SARIF_OUT="${OUTPUT_DIR}/findings.sarif"
TIDY_LOG="/tmp/zephyr_tidy.log"

mkdir -p "${OUTPUT_DIR}"

echo "[zephyr] Running clang-tidy on Zephyr kernel source..."

# Collect core kernel + subsystem source files (skip arch-specific asm ports)
FILES=$(find "${ZEPHYR_ROOT}/kernel" "${ZEPHYR_ROOT}/lib/os" \
             "${ZEPHYR_ROOT}/subsys/bluetooth" \
             "${ZEPHYR_ROOT}/drivers/gpio" \
        -name "*.c" 2>/dev/null \
    | grep -v -i "test" || true)
FILES=$(echo "$FILES" | grep -v -i "sample" | head -80 || true)

FILE_COUNT=$(echo "$FILES" | grep -c "\.c$" || true)
echo "[zephyr] Analyzing ${FILE_COUNT} source files..."

if [ -z "$FILES" ]; then
    echo "[zephyr] No source files found, exiting"
    exit 1
fi

# shellcheck disable=SC2086
clang-tidy \
    --checks="clang-analyzer-*,bugprone-*,cert-*" \
    $FILES \
    -- \
    -fsyntax-only \
    -I"${ZEPHYR_ROOT}/include" \
    -I"${ZEPHYR_ROOT}/kernel/include" \
    -I"${ZEPHYR_ROOT}/lib/libc/minimal/include" \
    -I"${ZEPHYR_ROOT}/subsys/bluetooth" \
    -DCONFIG_NUM_COOP_PRIORITIES=16 \
    -DCONFIG_NUM_PREEMPT_PRIORITIES=15 \
    -DCONFIG_MAIN_STACK_SIZE=8192 \
    -DCONFIG_HEAP_MEM_POOL_SIZE=262144 \
    -DCONFIG_SYS_CLOCK_TICKS_PER_SEC=100 \
    -DCONFIG_TIMESLICING=1 \
    -D__ZEPHYR__=1 \
    >"${TIDY_LOG}" 2>&1 || true

echo "[zephyr] Converting to SARIF..."

python3 - <<'PYEOF'
import json, pathlib, re

output_sarif = pathlib.Path("/output/findings.sarif")
log_text = pathlib.Path("/tmp/zephyr_tidy.log").read_text()

findings = []
pattern = re.compile(r"^(.+?):(\d+):(\d+): (warning|error|note): (.+?) \[(.+?)\]$", re.MULTILINE)

for m in pattern.finditer(log_text):
    filepath, line, col, level, message, checker = m.groups()
    if level == "note":
        continue

    cwe = None
    if "buffer" in checker.lower() or "overflow" in checker.lower():
        cwe = "CWE-120"
    elif "null" in checker.lower() or "deref" in checker.lower():
        cwe = "CWE-476"
    elif "leak" in checker.lower() or "memory" in checker.lower():
        cwe = "CWE-401"
    elif "use-after" in checker.lower() or "dangling" in checker.lower():
        cwe = "CWE-416"
    elif "integer" in checker.lower() or "overflow" in checker.lower():
        cwe = "CWE-190"
    elif "dead" in checker.lower() or "lock" in checker.lower():
        cwe = "CWE-833"

    findings.append({
        "ruleId": checker,
        "level": "error" if level == "error" else "warning",
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": filepath.lstrip("/")},
                "region": {"startLine": int(line), "startColumn": int(col)},
            }
        }],
        "taxa": [{"id": cwe, "toolComponent": {"name": "CWE"}}] if cwe else [],
    })

sarif = {
    "version": "2.1.0",
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
    "runs": [{
        "tool": {
            "driver": {
                "name": "Clang Static Analyzer",
                "version": "clang-tidy",
                "rules": [],
            }
        },
        "results": findings,
    }]
}

output_sarif.parent.mkdir(parents=True, exist_ok=True)
output_sarif.write_text(json.dumps(sarif, indent=2))
print(f"[zephyr] SARIF written: {output_sarif} ({len(findings)} findings)")
PYEOF

echo "[zephyr] Done. SARIF at: ${SARIF_OUT}"

echo "[zephyr] Running LLM vulnerability discovery..."
python3 /discover.py
