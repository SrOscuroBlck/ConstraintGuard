import shlex
import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel


class AnalyzerError(Exception):
    pass


class ScanBuildConfig(BaseModel):
    source_path: Path
    build_command: str
    output_dir: Path

    model_config = {"arbitrary_types_allowed": True}


class ScanBuildResult(BaseModel):
    sarif_paths: list[Path]
    exit_code: int
    sarif_dir: Path

    model_config = {"arbitrary_types_allowed": True}


def run_scan_build(config: ScanBuildConfig) -> ScanBuildResult:
    _require_scan_build_on_path()
    sarif_dir = _prepare_sarif_output_dir(config.output_dir)
    command = _build_scan_build_command(sarif_dir, config.build_command)
    exit_code = _execute_command(command, cwd=config.source_path)
    sarif_paths = _collect_sarif_files(sarif_dir)
    return ScanBuildResult(
        sarif_paths=sarif_paths,
        exit_code=exit_code,
        sarif_dir=sarif_dir,
    )


def _require_scan_build_on_path() -> None:
    if shutil.which("scan-build") is None:
        raise AnalyzerError(
            "scan-build not found on PATH. "
            "Install Clang/LLVM and ensure scan-build is accessible."
        )


def _prepare_sarif_output_dir(output_dir: Path) -> Path:
    sarif_dir = output_dir / "sarif"
    if sarif_dir.exists():
        shutil.rmtree(sarif_dir)
    sarif_dir.mkdir(parents=True)
    return sarif_dir


def _build_scan_build_command(sarif_dir: Path, build_command: str) -> list[str]:
    build_parts = shlex.split(build_command)
    return [
        "scan-build",
        "-o", str(sarif_dir),
        "-sarif",
        *build_parts,
    ]


def _execute_command(command: list[str], cwd: Path | None = None) -> int:
    result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        raise AnalyzerError(
            f"scan-build exited with non-zero code {result.returncode}. "
            f"Verify the build command succeeds independently before running through scan-build. "
            f"Full command: {' '.join(command)}"
        )
    return result.returncode


def _collect_sarif_files(sarif_dir: Path) -> list[Path]:
    return sorted(sarif_dir.rglob("*.sarif"))
