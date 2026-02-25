from datetime import datetime, timezone
from pathlib import Path

from constraintguard.reporting import (
    print_report_to_console,
    write_json_report,
    write_markdown_report,
)
from constraintguard.models import (
    ConstraintProvenance,
    ConstraintSourceType,
    FieldProvenance,
    HardwareSpec,
    ReportSummary,
    RiskItem,
    RiskReport,
    RuleFiring,
    RunMetadata,
    SeverityTier,
    TierCounts,
    Vulnerability,
    score_to_tier,
)


def build_mock_hardware_spec() -> HardwareSpec:
    return HardwareSpec(
        platform="cortex-m4",
        ram_size_bytes=20480,
        flash_size_bytes=262144,
        stack_size_bytes=2048,
        heap_size_bytes=4096,
        max_interrupt_latency_us=50,
        critical_functions=["control_loop", "isr_uart"],
        safety_level="ISO26262-ASIL-B",
    )


def build_mock_provenance() -> ConstraintProvenance:
    return ConstraintProvenance(
        field_origins={
            "ram_size_bytes": FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path="examples/configs/tight.yml",
            ),
            "flash_size_bytes": FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path="examples/configs/tight.yml",
            ),
            "stack_size_bytes": FieldProvenance(
                source_type=ConstraintSourceType.LINKER_SCRIPT,
                source_path="examples/vuln_demo/linker.ld",
                extraction_note="Extracted from _stack_size symbol",
            ),
            "heap_size_bytes": FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path="examples/configs/tight.yml",
            ),
            "safety_level": FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path="examples/configs/tight.yml",
            ),
            "critical_functions": FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path="examples/configs/tight.yml",
            ),
            "max_interrupt_latency_us": FieldProvenance(
                source_type=ConstraintSourceType.YAML,
                source_path="examples/configs/tight.yml",
            ),
        }
    )


def build_mock_vulnerabilities() -> list[Vulnerability]:
    return [
        Vulnerability(
            tool="clang-sa",
            rule_id="core.StackAddressEscape",
            message="Address of stack memory associated with local variable 'buf' returned to caller",
            path="src/comm.c",
            start_line=42,
            start_col=5,
            function="send_response",
            cwe="CWE-562",
            category="stack-overflow",
        ),
        Vulnerability(
            tool="clang-sa",
            rule_id="unix.Malloc",
            message="Potential memory leak",
            path="src/sensor.c",
            start_line=118,
            start_col=12,
            function="read_sensor_data",
            cwe="CWE-401",
            category="memory-leak",
        ),
        Vulnerability(
            tool="clang-sa",
            rule_id="core.NullDereference",
            message="Dereference of null pointer",
            path="src/control.c",
            start_line=85,
            start_col=3,
            function="control_loop",
            cwe="CWE-476",
            category="null-dereference",
        ),
    ]


def build_mock_risk_items(
    vulnerabilities: list[Vulnerability],
) -> list[RiskItem]:
    items: list[RiskItem] = []

    score_0 = 88
    items.append(
        RiskItem(
            vulnerability=vulnerabilities[0],
            base_score=60,
            final_score=score_0,
            tier=score_to_tier(score_0),
            rule_firings=[
                RuleFiring(
                    rule_id="mem-tight-stack-overflow",
                    delta=20,
                    rationale="Stack overflow risk escalated: stack budget is 2048 bytes",
                    constraints_used=["stack_size_bytes"],
                ),
                RuleFiring(
                    rule_id="safety-critical-context",
                    delta=8,
                    rationale="Finding in safety-critical context (ISO26262-ASIL-B)",
                    constraints_used=["safety_level"],
                ),
            ],
            explanation=(
                "Stack address escape in send_response is critical under a 2KB stack budget. "
                "Safety context ISO26262-ASIL-B further escalates this finding."
            ),
            remediation=(
                "Avoid returning pointers to stack-allocated buffers. "
                "Use a caller-provided buffer or a statically allocated region."
            ),
        )
    )

    score_1 = 72
    items.append(
        RiskItem(
            vulnerability=vulnerabilities[1],
            base_score=50,
            final_score=score_1,
            tier=score_to_tier(score_1),
            rule_firings=[
                RuleFiring(
                    rule_id="mem-tight-heap-leak",
                    delta=15,
                    rationale="Memory leak escalated: heap budget is 4096 bytes",
                    constraints_used=["heap_size_bytes"],
                ),
                RuleFiring(
                    rule_id="ram-pressure",
                    delta=7,
                    rationale="RAM is constrained to 20480 bytes; leaks exhaust available memory faster",
                    constraints_used=["ram_size_bytes"],
                ),
            ],
            explanation=(
                "Memory leak in read_sensor_data is high-risk under a 4KB heap budget "
                "with only 20KB total RAM."
            ),
            remediation=(
                "Ensure all allocated memory is freed on every code path. "
                "Consider using a pool allocator sized to the heap budget."
            ),
        )
    )

    score_2 = 92
    items.append(
        RiskItem(
            vulnerability=vulnerabilities[2],
            base_score=55,
            final_score=score_2,
            tier=score_to_tier(score_2),
            rule_firings=[
                RuleFiring(
                    rule_id="critical-function-hit",
                    delta=25,
                    rationale="Null dereference in critical function 'control_loop'",
                    constraints_used=["critical_functions"],
                ),
                RuleFiring(
                    rule_id="safety-critical-context",
                    delta=8,
                    rationale="Finding in safety-critical context (ISO26262-ASIL-B)",
                    constraints_used=["safety_level"],
                ),
                RuleFiring(
                    rule_id="interrupt-latency-risk",
                    delta=4,
                    rationale="Crash in control path may violate 50us interrupt latency budget",
                    constraints_used=["max_interrupt_latency_us"],
                ),
            ],
            explanation=(
                "Null dereference in control_loop is critical: this is a marked critical function "
                "under ISO26262-ASIL-B with a 50us interrupt latency budget."
            ),
            remediation=(
                "Add null checks before dereferencing pointers in control_loop. "
                "Consider using defensive coding patterns required by ASIL-B."
            ),
        )
    )

    items.sort(key=lambda item: item.final_score, reverse=True)
    return items


def compute_tier_counts(items: list[RiskItem]) -> TierCounts:
    return TierCounts(
        critical=sum(1 for i in items if i.tier == SeverityTier.CRITICAL),
        high=sum(1 for i in items if i.tier == SeverityTier.HIGH),
        medium=sum(1 for i in items if i.tier == SeverityTier.MEDIUM),
        low=sum(1 for i in items if i.tier == SeverityTier.LOW),
    )


def generate_mock_report() -> RiskReport:
    hardware_spec = build_mock_hardware_spec()
    provenance = build_mock_provenance()
    vulnerabilities = build_mock_vulnerabilities()
    risk_items = build_mock_risk_items(vulnerabilities)
    tier_counts = compute_tier_counts(risk_items)

    summary = ReportSummary(
        total_findings=len(risk_items),
        tier_counts=tier_counts,
        top_findings=[item.vulnerability.rule_id for item in risk_items[:3]],
    )

    run_metadata = RunMetadata(
        tool_version="0.1.0",
        timestamp=datetime.now(timezone.utc),
        command=(
            "constraintguard run "
            "--source examples/vuln_demo "
            "--build-cmd 'make' "
            "--config examples/configs/tight.yml "
            "--out out/demo"
        ),
        source_path="examples/vuln_demo",
        config_path="examples/configs/tight.yml",
    )

    return RiskReport(
        run_metadata=run_metadata,
        hardware_spec=hardware_spec,
        provenance=provenance,
        summary=summary,
        items=risk_items,
    )


if __name__ == "__main__":
    report = generate_mock_report()
    print_report_to_console(report)
    output_dir = Path(__file__).parent
    json_path = write_json_report(report, output_dir)
    md_path = write_markdown_report(report, output_dir)
    print(f"JSON report written to {json_path}")
    print(f"Markdown report written to {md_path}")
