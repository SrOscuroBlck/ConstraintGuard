#!/usr/bin/env bash
# Scan FreeRTOS-Kernel with Clang Static Analyzer and produce SARIF.
# This script runs inside Docker OR locally if you have the tools installed.
#
# Usage (Docker):
#   docker build -t cg-scan-freertos eval/sarif_acquisition/freertos/
#   docker run --rm -v "$(pwd)/eval/data/sarif/freertos:/output" cg-scan-freertos
#
# Usage (local, if clang + arm toolchain available):
#   bash eval/sarif_acquisition/freertos/run_scan.sh

set -euo pipefail

REPO_DIR="${FREERTOS_DIR:-/src/freertos}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
SARIF_OUT="${OUTPUT_DIR}/findings.sarif"

mkdir -p "${OUTPUT_DIR}"

echo "[freertos] Scanning with Clang Static Analyzer..."

# Strategy 1: scan-build with SARIF output (Clang 16+)
# Compile the portable GCC ARM_CM3 layer with -fsyntax-only (no linker needed)
SCAN_BUILD_OUT=$(mktemp -d)

cd "${REPO_DIR}"

# Create a minimal compile_commands.json for clang-tidy
python3 - <<'PYEOF'
import json, pathlib

src_root = pathlib.Path("/src/freertos")
sources = list(src_root.rglob("*.c"))

# Core kernel files (tasks.c, queue.c, list.c, etc.) + heap managers + ARM_CM3 portable layer
filtered = [
    f for f in sources
    if "portable/GCC/ARM_CM3" in str(f)
    or "portable/MemMang" in str(f)
    or (
        "portable" not in str(f)
        and "tests" not in str(f)
        and "demo" not in str(f).lower()
    )
]

compile_commands = []
for src in filtered:
    compile_commands.append({
        "directory": str(src_root),
        "file": str(src),
        "command": (
            f"clang -fsyntax-only -w "
            f"-I{src_root}/include "
            f"-I{src_root}/portable/GCC/ARM_CM3 "
            f"-I{src_root}/portable/MemMang "
            f"-DGCC_ARMCM3 "
            f"-D__ARM_ARCH_7M__=1 -D__thumb__=1 "
            f"{src}"
        ),
    })

with open("/src/freertos/compile_commands.json", "w") as f:
    json.dump(compile_commands, f, indent=2)

print(f"Generated compile_commands.json with {len(compile_commands)} translation units")
PYEOF

# Run clang-tidy with SARIF export
echo "[freertos] Running clang-tidy..."
TIDY_LOG="/tmp/freertos_tidy.log"

clang-tidy \
    --checks="clang-analyzer-*,bugprone-*,cert-*" \
    -p "/src/freertos" \
    $(find /src/freertos -name "*.c" \
        | grep -E "portable/GCC/ARM_CM3|portable/MemMang" \
        | head -60) \
    $(find /src/freertos -name "*.c" \
        | grep -v "portable" | grep -v -i "test" | grep -v -i "demo" \
        | head -20) \
    >"${TIDY_LOG}" 2>&1 || true

echo "[freertos] Converting to SARIF..."

python3 - <<'PYEOF'
"""Convert clang-tidy output to SARIF 2.1.0 format."""
import json, pathlib, re

output_sarif = pathlib.Path("/output/findings.sarif")

log_text = pathlib.Path("/tmp/freertos_tidy.log").read_text()

findings = []
# Parse clang-tidy text output: file:line:col: severity: message [checker]
pattern = re.compile(r"^(.+?):(\d+):(\d+): (warning|error|note): (.+?) \[(.+?)\]$", re.MULTILINE)

for m in pattern.finditer(log_text):
    filepath, line, col, level, message, checker = m.groups()
    if level == "note":
        continue

    # Map checker to CWE
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
print(f"[freertos] SARIF written: {output_sarif} ({len(findings)} findings)")
PYEOF

echo "[freertos] Done. SARIF at: ${SARIF_OUT}"
