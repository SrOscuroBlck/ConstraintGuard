from pathlib import Path

from constraintguard.models.risk_report import RiskReport

_REPORT_FILENAME = "report.json"


def write_json_report(report: RiskReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / _REPORT_FILENAME
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report_path
