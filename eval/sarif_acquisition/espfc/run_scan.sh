#!/usr/bin/env bash
# Scan esp-fc (drone flight controller) with Clang Static Analyzer.
# Targets ESP32 embedded firmware with IEC61508-SIL2 safety context.
#
# Usage (Docker):
#   docker build -t cg-scan-espfc -f eval/sarif_acquisition/espfc/Dockerfile eval/sarif_acquisition/
#   docker run --rm \
#     -v "$(pwd)/eval/data/sarif/espfc:/output" \
#     -e CONSTRAINTGUARD_LLM_API_KEY \
#     -e CONSTRAINTGUARD_LLM_MODEL \
#     -e CONSTRAINTGUARD_LLM_PROVIDER \
#     cg-scan-espfc
#
# Without LLM env vars the scan still runs; discoveries.json will be empty.
#
# Note: esp-fc uses Arduino + ESP-IDF framework via PlatformIO.
# Since ESP32 uses Xtensa architecture, we use clang-tidy with host
# compilation to get static analysis findings from the C++ source.

set -euo pipefail

ESPFC_DIR="${ESPFC_DIR:-/src/espfc}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
SARIF_OUT="${OUTPUT_DIR}/findings.sarif"

mkdir -p "${OUTPUT_DIR}"

echo "[espfc] Running clang-tidy on esp-fc source..."

python3 - <<'PYEOF'
import json, pathlib, re, subprocess, sys

src_root = pathlib.Path("/src/espfc")
output_sarif = pathlib.Path("/output/findings.sarif")

# esp-fc source is in lib/ and src/
target_dirs = [
    src_root / "lib" / "Espfc" / "src",
    src_root / "src",
]

source_files = []
for d in target_dirs:
    if d.exists():
        source_files.extend(d.rglob("*.cpp"))
        source_files.extend(d.rglob("*.c"))

source_files = [f for f in source_files if "test" not in str(f).lower()][:100]
print(f"[espfc] Analyzing {len(source_files)} source files...")

# Arduino/ESP32 compatibility includes
# We use a minimal set of stubs to allow analysis without the full SDK
common_flags = [
    f"-I{src_root}/lib/Espfc/src",
    f"-I{src_root}/src",
    "-std=c++17",
    "-DESP32=1",
    "-DARDUINO=10813",
    "-DARDUINO_ESP32_DEV=1",
    "-DF_CPU=240000000L",
    "-DCORE_DEBUG_LEVEL=0",
    "-x", "c++",
    "-fsyntax-only",
    # Suppress platform-specific errors
    "-Wno-unknown-pragmas",
    "-Wno-unused-function",
]

findings = []
pattern = re.compile(r"^(.+?):(\d+):(\d+): (warning|error): (.+?) \[(.+?)\]$", re.MULTILINE)

cwe_map = {
    "buffer": "CWE-120",
    "overflow": "CWE-120",
    "null": "CWE-476",
    "deref": "CWE-476",
    "leak": "CWE-401",
    "memory": "CWE-401",
    "use-after": "CWE-416",
    "dangling": "CWE-416",
    "integer": "CWE-190",
    "dead": "CWE-833",
    "lock": "CWE-833",
    "divide": "CWE-369",
    "uninit": "CWE-457",
}

for src in source_files:
    try:
        result = subprocess.run(
            ["clang-tidy",
             "--checks=clang-analyzer-*,bugprone-*,cert-*",
             str(src),
             "--",
             ] + common_flags,
            capture_output=True, text=True, timeout=45,
        )
    except subprocess.TimeoutExpired:
        print(f"  Timeout: {src.name}")
        continue

    output = result.stdout + result.stderr
    for m in pattern.finditer(output):
        filepath, line, col, level, message, checker = m.groups()
        if level == "note":
            continue

        cwe = None
        checker_lower = checker.lower()
        for keyword, cwe_id in cwe_map.items():
            if keyword in checker_lower or keyword in message.lower():
                cwe = cwe_id
                break

        # Detect ISR-related functions from message/location context
        function_hint = None
        if any(kw in message.lower() for kw in ["isr", "interrupt", "handler"]):
            function_hint = "handle_isr"
        elif "pid" in message.lower():
            function_hint = "pid_controller"
        elif "motor" in message.lower():
            function_hint = "motor_control"
        elif "imu" in message.lower():
            function_hint = "imu_read"

        finding = {
            "ruleId": checker,
            "level": "warning",
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filepath.lstrip("/")},
                    "region": {"startLine": int(line), "startColumn": int(col)},
                }
            }],
        }
        if cwe:
            finding["taxa"] = [{"id": cwe, "toolComponent": {"name": "CWE"}}]
        if function_hint:
            finding["message"]["text"] = f"[{function_hint}] " + message

        findings.append(finding)

sarif = {
    "version": "2.1.0",
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "Clang Static Analyzer", "version": "clang-tidy"}},
        "results": findings,
    }]
}

output_sarif.parent.mkdir(parents=True, exist_ok=True)
output_sarif.write_text(json.dumps(sarif, indent=2))
print(f"[espfc] SARIF written: {output_sarif} ({len(findings)} findings)")
PYEOF

echo "[espfc] Done. SARIF at: ${SARIF_OUT}"

echo "[espfc] Running LLM vulnerability discovery..."
python3 /discover.py
