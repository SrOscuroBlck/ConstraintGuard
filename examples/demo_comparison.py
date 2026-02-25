from pathlib import Path

from constraintguard.models.enums import SeverityTier
from constraintguard.models.hardware_spec import HardwareSpec
from constraintguard.models.risk_report import RiskItem
from constraintguard.models.vulnerability import Vulnerability
from constraintguard.parsers.yaml_parser import parse_yaml_constraints
from constraintguard.scoring.engine import score_all

_REPO_ROOT = Path(__file__).parent.parent
_TIGHT_CONFIG = _REPO_ROOT / "examples" / "configs" / "tight.yml"
_RELAXED_CONFIG = _REPO_ROOT / "examples" / "configs" / "relaxed.yml"
_SECTION = "═" * 72
_RULE = "─" * 72

_DEMO_VULNERABILITIES: list[Vulnerability] = [
    Vulnerability(
        tool="clang-sa",
        rule_id="security.insecureAPI.strcpy",
        message="Call to function 'strcpy' is insecure; use 'strlcpy' or 'strncpy' instead",
        path="examples/vuln_demo/main.c",
        start_line=15,
        function="copy_input",
        cwe="CWE-120",
        category="buffer_overflow",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="core.NullDereference",
        message="Dereference of null pointer (loaded from variable 'sensor_value')",
        path="examples/vuln_demo/main.c",
        start_line=22,
        function="read_sensor",
        cwe="CWE-476",
        category="null_deref",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="unix.Malloc",
        message="Potential memory leak of memory pointed to by 'packet'",
        path="examples/vuln_demo/main.c",
        start_line=35,
        function="build_packet",
        cwe="CWE-401",
        category="leak",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="unix.Malloc",
        message="Use of memory after it is freed",
        path="examples/vuln_demo/main.c",
        start_line=52,
        function="process_buffer",
        cwe="CWE-416",
        category="use_after_free",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="alpha.core.CastSize",
        message="Cast from integer to pointer of greater size leads to integer overflow",
        path="examples/vuln_demo/main.c",
        start_line=58,
        function="allocate_matrix",
        cwe="CWE-190",
        category="integer_overflow",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="core.uninitialized.UndefReturn",
        message="Undefined or garbage value returned to caller",
        path="examples/vuln_demo/main.c",
        start_line=69,
        function="compute_checksum",
        cwe=None,
        category="uninitialized",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="security.insecureAPI.strcpy",
        message="Call to function 'strcpy' is insecure; use 'strlcpy' or 'strncpy' instead",
        path="examples/vuln_demo/main.c",
        start_line=76,
        function="isr_uart",
        cwe="CWE-120",
        category="buffer_overflow",
    ),
    Vulnerability(
        tool="clang-sa",
        rule_id="core.NullDereference",
        message="Dereference of null pointer (loaded from variable 'measured')",
        path="examples/vuln_demo/main.c",
        start_line=83,
        function="control_loop",
        cwe="CWE-476",
        category="null_deref",
    ),
]

_TIER_ORDER = {
    SeverityTier.CRITICAL: 4,
    SeverityTier.HIGH: 3,
    SeverityTier.MEDIUM: 2,
    SeverityTier.LOW: 1,
}

_TIER_WIDTH = 8


def _tier_label(tier: SeverityTier) -> str:
    return tier.value.ljust(_TIER_WIDTH)


def _fired_rule_ids(item: RiskItem) -> str:
    if not item.rule_firings:
        return "none"
    return ", ".join(f"{f.rule_id}({f.delta:+d})" for f in item.rule_firings)


def _tier_changed(tight_tier: SeverityTier, relaxed_tier: SeverityTier) -> bool:
    return _TIER_ORDER[tight_tier] != _TIER_ORDER[relaxed_tier]


def _print_finding_row(
    rank: int,
    vuln: Vulnerability,
    tight_item: RiskItem,
    relaxed_item: RiskItem,
) -> None:
    location = f"{vuln.path}:{vuln.start_line}"
    fn_label = f"  in {vuln.function}" if vuln.function else ""
    changed = _tier_changed(tight_item.tier, relaxed_item.tier)
    change_marker = "  ← TIER CHANGED" if changed else ""

    print(f"  [{rank}] {vuln.category}  [{vuln.rule_id}]")
    print(f"      {location}{fn_label}")
    print(
        f"      Tight:   {_tier_label(tight_item.tier)}  score={tight_item.final_score:3d}"
        f"  rules: {_fired_rule_ids(tight_item)}"
    )
    print(
        f"      Relaxed: {_tier_label(relaxed_item.tier)}  score={relaxed_item.final_score:3d}"
        f"  rules: {_fired_rule_ids(relaxed_item)}"
        f"{change_marker}"
    )
    print()


def _build_finding_index(items: list[RiskItem]) -> dict[str, RiskItem]:
    return {
        f"{item.vulnerability.path}:{item.vulnerability.start_line}:{item.vulnerability.function}": item
        for item in items
    }


def _lookup_item(index: dict[str, RiskItem], vuln: Vulnerability) -> RiskItem:
    key = f"{vuln.path}:{vuln.start_line}:{vuln.function}"
    return index[key]


def _count_tier_changes(
    vulns: list[Vulnerability],
    tight_index: dict[str, RiskItem],
    relaxed_index: dict[str, RiskItem],
) -> int:
    return sum(
        1
        for v in vulns
        if _tier_changed(
            _lookup_item(tight_index, v).tier,
            _lookup_item(relaxed_index, v).tier,
        )
    )


def _print_tier_distribution(label: str, items: list[RiskItem]) -> None:
    counts = {tier: sum(1 for i in items if i.tier == tier) for tier in SeverityTier}
    print(f"  {label}")
    for tier in [SeverityTier.CRITICAL, SeverityTier.HIGH, SeverityTier.MEDIUM, SeverityTier.LOW]:
        bar = "█" * counts[tier] + "░" * (max(counts.values()) - counts[tier])
        print(f"    {tier.value.ljust(8)}  {bar}  {counts[tier]}")
    print()


def _print_hardware_summary(label: str, spec: HardwareSpec) -> None:
    stack = f"{spec.stack_size_bytes}B" if spec.stack_size_bytes else "unknown"
    heap = f"{spec.heap_size_bytes}B" if spec.heap_size_bytes else "unknown"
    ram = f"{spec.ram_size_bytes}B" if spec.ram_size_bytes else "unknown"
    latency = f"{spec.max_interrupt_latency_us}µs" if spec.max_interrupt_latency_us else "unknown"
    safety = spec.safety_level or "none"
    crit = ", ".join(spec.critical_functions) if spec.critical_functions else "none"
    print(f"  {label}")
    print(f"    platform={spec.platform}  stack={stack}  heap={heap}  ram={ram}")
    print(f"    latency={latency}  safety={safety}")
    print(f"    critical_functions=[{crit}]")
    print()


def run_comparison() -> None:
    tight_spec, _ = parse_yaml_constraints(_TIGHT_CONFIG)
    relaxed_spec, _ = parse_yaml_constraints(_RELAXED_CONFIG)

    tight_items = score_all(_DEMO_VULNERABILITIES, tight_spec)
    relaxed_items = score_all(_DEMO_VULNERABILITIES, relaxed_spec)

    tight_index = _build_finding_index(tight_items)
    relaxed_index = _build_finding_index(relaxed_items)
    tier_change_count = _count_tier_changes(_DEMO_VULNERABILITIES, tight_index, relaxed_index)

    print()
    print(_SECTION)
    print("  ConstraintGuard — Constraint Comparison Demo")
    print("  Same code, same findings, different constraint profiles → different risk tiers")
    print(_SECTION)
    print()

    print(_RULE)
    print("  Constraint Profiles")
    print(_RULE)
    _print_hardware_summary(f"tight  ({_TIGHT_CONFIG.name})", tight_spec)
    _print_hardware_summary(f"relaxed ({_RELAXED_CONFIG.name})", relaxed_spec)

    print(_RULE)
    print("  Severity Distribution")
    print(_RULE)
    _print_tier_distribution("tight", tight_items)
    _print_tier_distribution("relaxed", relaxed_items)

    print(_RULE)
    print("  Per-Finding Comparison  (← TIER CHANGED marks constraint-driven re-rankings)")
    print(_RULE)
    print()

    for rank, vuln in enumerate(_DEMO_VULNERABILITIES, start=1):
        tight_item = _lookup_item(tight_index, vuln)
        relaxed_item = _lookup_item(relaxed_index, vuln)
        _print_finding_row(rank, vuln, tight_item, relaxed_item)

    print(_SECTION)
    print(
        f"  {tier_change_count} of {len(_DEMO_VULNERABILITIES)} findings changed severity tier"
        f" between tight and relaxed profiles."
    )
    print("  Identical SARIF input — constraint-aware prioritization drives the difference.")
    print(_SECTION)
    print()


if __name__ == "__main__":
    run_comparison()
