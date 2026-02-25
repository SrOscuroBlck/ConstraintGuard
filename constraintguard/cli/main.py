import argparse
import sys
from pathlib import Path

from constraintguard.analyzers.scan_build_runner import (
    AnalyzerError,
    ScanBuildConfig,
    run_scan_build,
)
from constraintguard.models.enums import SeverityTier
from constraintguard.models.risk_report import RiskReport
from constraintguard.pipeline import run_score_pipeline

_DEFAULT_TOP_K = 10

_FAIL_ON_CHOICES = [tier.value.lower() for tier in SeverityTier]

_EXIT_CODE_THRESHOLD_EXCEEDED = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="constraintguard",
        description="Constraint-aware security prioritization for embedded C/C++ projects",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Run analyzer, score findings, and generate reports",
    )
    run_parser.add_argument(
        "--source", type=Path, required=True, help="Path to the source repository"
    )
    run_parser.add_argument(
        "--build-cmd", type=str, required=True, help="Build command for the project"
    )
    run_parser.add_argument(
        "--config", type=Path, required=True, help="Path to .constraintguard.yml"
    )
    run_parser.add_argument(
        "--linker-script", type=Path, default=None, help="Path to linker script (.ld)"
    )
    run_parser.add_argument(
        "--out", type=Path, required=True, help="Output directory for reports"
    )
    run_parser.add_argument(
        "--top-k", type=int, default=_DEFAULT_TOP_K, help="Number of top findings to display (default: 10)"
    )
    run_parser.add_argument(
        "--fail-on", type=str, choices=_FAIL_ON_CHOICES, default=None,
        help="Exit with code 2 if any finding meets or exceeds this tier (critical, high, medium, low)",
    )

    score_parser = subparsers.add_parser(
        "score",
        help="Score existing SARIF findings without running analyzer",
    )
    score_parser.add_argument(
        "--sarif", type=Path, required=True, nargs="+", help="Path(s) to SARIF file(s)"
    )
    score_parser.add_argument(
        "--config", type=Path, required=True, help="Path to .constraintguard.yml"
    )
    score_parser.add_argument(
        "--linker-script", type=Path, default=None, help="Path to linker script (.ld)"
    )
    score_parser.add_argument(
        "--out", type=Path, required=True, help="Output directory for reports"
    )
    score_parser.add_argument(
        "--top-k", type=int, default=_DEFAULT_TOP_K, help="Number of top findings to display (default: 10)"
    )
    score_parser.add_argument(
        "--fail-on", type=str, choices=_FAIL_ON_CHOICES, default=None,
        help="Exit with code 2 if any finding meets or exceeds this tier (critical, high, medium, low)",
    )

    return parser


def _validate_paths_exist(*paths: Path | None) -> None:
    for path in paths:
        if path is not None and not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")


def _check_threshold(report: RiskReport, fail_on: str | None) -> int:
    if not fail_on:
        return 0

    threshold_tier = SeverityTier(fail_on.upper())
    tier_rank = {SeverityTier.CRITICAL: 4, SeverityTier.HIGH: 3, SeverityTier.MEDIUM: 2, SeverityTier.LOW: 1}
    threshold_rank = tier_rank[threshold_tier]

    for item in report.items:
        if tier_rank.get(item.tier, 0) >= threshold_rank:
            count = sum(1 for i in report.items if tier_rank.get(i.tier, 0) >= threshold_rank)
            print(
                f"\nPolicy violation: {count} finding(s) at {threshold_tier.value} or above "
                f"(--fail-on {fail_on})"
            )
            return _EXIT_CODE_THRESHOLD_EXCEEDED

    return 0


def _build_command_string(args: argparse.Namespace) -> str:
    parts = ["constraintguard", args.command]
    for key, value in vars(args).items():
        if key == "command" or value is None:
            continue
        flag = f"--{key.replace('_', '-')}"
        if isinstance(value, bool):
            if value:
                parts.append(flag)
        elif isinstance(value, list):
            for item in value:
                parts.extend([flag, str(item)])
        else:
            parts.extend([flag, str(value)])
    return " ".join(parts)


def handle_run(args: argparse.Namespace) -> int:
    _validate_paths_exist(args.source, args.config, args.linker_script)

    if not args.source.is_dir():
        print(f"Error: --source must be a directory: {args.source}")
        return 1

    try:
        scan_config = ScanBuildConfig(
            source_path=args.source,
            build_command=args.build_cmd,
            output_dir=args.out,
        )
        scan_result = run_scan_build(scan_config)
    except AnalyzerError as exc:
        print(f"Analyzer error: {exc}")
        return 1

    if not scan_result.sarif_paths:
        print("Warning: scan-build produced no SARIF files.")
        return 1

    report = run_score_pipeline(
        sarif_paths=scan_result.sarif_paths,
        config_path=args.config,
        linker_script_path=args.linker_script,
        out_dir=args.out,
        top_k=args.top_k,
        command=_build_command_string(args),
        source_path=str(args.source),
    )
    return _check_threshold(report, args.fail_on)


def handle_score(args: argparse.Namespace) -> int:
    sarif_paths: list[Path] = args.sarif
    _validate_paths_exist(args.config, args.linker_script, *sarif_paths)

    report = run_score_pipeline(
        sarif_paths=sarif_paths,
        config_path=args.config,
        linker_script_path=args.linker_script,
        out_dir=args.out,
        top_k=args.top_k,
        command=_build_command_string(args),
    )
    return _check_threshold(report, args.fail_on)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        match args.command:
            case "run":
                return handle_run(args)
            case "score":
                return handle_score(args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1
    except ValueError as exc:
        print(f"Configuration error: {exc}")
        return 1

    return 0


def cli_entry() -> None:
    raise SystemExit(main())
