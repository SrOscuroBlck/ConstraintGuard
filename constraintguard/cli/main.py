import argparse
import sys
from pathlib import Path


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
        "--out", type=Path, required=True, help="Output directory for reports"
    )
    run_parser.add_argument(
        "--enrich", type=str, default=None, help="Enable enrichment (e.g., topK=10)"
    )

    score_parser = subparsers.add_parser(
        "score",
        help="Score existing SARIF findings without running analyzer",
    )
    score_parser.add_argument(
        "--sarif", type=Path, required=True, help="Path to SARIF file"
    )
    score_parser.add_argument(
        "--config", type=Path, required=True, help="Path to .constraintguard.yml"
    )
    score_parser.add_argument(
        "--out", type=Path, required=True, help="Output directory for reports"
    )

    return parser


def handle_run(args: argparse.Namespace) -> int:
    print("ConstraintGuard run")
    print(f"  Source:    {args.source}")
    print(f"  Build:    {args.build_cmd}")
    print(f"  Config:   {args.config}")
    print(f"  Output:   {args.out}")
    if args.enrich:
        print(f"  Enrich:   {args.enrich}")
    print("Pipeline not yet implemented. See docs/tasks/TASKS.md for status.")
    return 0


def handle_score(args: argparse.Namespace) -> int:
    print("ConstraintGuard score")
    print(f"  SARIF:    {args.sarif}")
    print(f"  Config:   {args.config}")
    print(f"  Output:   {args.out}")
    print("Pipeline not yet implemented. See docs/tasks/TASKS.md for status.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    match args.command:
        case "run":
            return handle_run(args)
        case "score":
            return handle_score(args)

    return 0


def cli_entry() -> None:
    raise SystemExit(main())
