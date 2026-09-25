"""Train, independently evaluate, and conditionally approve a model candidate."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from itertools import combinations
from pathlib import Path

from email_analyzer.evaluate_evidence_ml import _gate_probability, _positive_row_count
from email_analyzer.manifest_independence import check_independence


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=True)
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    return completed


def main() -> None:
    parser = argparse.ArgumentParser(description="Gated evidence-model candidate pipeline")
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("external_manifest", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("approved", type=Path)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--text-bins", type=int, default=4096)
    # Match the evaluator before preflight, training, or any artifact writes.
    parser.add_argument("--external-min-rows", type=_positive_row_count, default=100)
    parser.add_argument("--external-min-auc", type=_gate_probability, default=.75)
    parser.add_argument("--external-max-fpr", type=_gate_probability, default=.15)
    parser.add_argument("--external-min-recall", type=_gate_probability, default=.65)
    args = parser.parse_args()
    training_metrics = args.candidate.with_suffix(".metrics.json")
    external_report = args.candidate.with_suffix(".external.json")
    status_path = args.candidate.with_suffix(".pipeline.json")
    # The trainer writes metrics even when its internal gate fails. Include this
    # sidecar before any preflight status output, directory creation, or training.
    artifacts = (args.candidate, args.approved, training_metrics, external_report, status_path)
    for left, right in combinations(artifacts, 2):
        if (left.resolve() == right.resolve()
                or (left.exists() and right.exists() and left.samefile(right))):
            parser.error("candidate, approved, training metrics, external report, and status paths must differ")

    # A failing preflight writes status too: protect the manifests before reading
    # them, not only before training or copying an approved candidate.
    for artifact in artifacts:
        for manifest in (args.training_manifest, args.external_manifest):
            if (artifact.resolve() == manifest.resolve()
                    or (artifact.exists() and manifest.exists() and artifact.samefile(manifest))):
                parser.error("pipeline output and input manifest paths must differ")

    args.candidate.parent.mkdir(parents=True, exist_ok=True)
    status = {"model_id": args.model_id, "trained": False, "external_gate_passed": False,
              "approved": False, "production_config_changed": False}

    try:
        status["input_independence"] = check_independence(args.training_manifest, args.external_manifest)
    except ValueError as exc:
        status["input_independence"] = {"passed": False, "error": str(exc)}
        status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(status, ensure_ascii=False, indent=2))
        raise SystemExit(2) from None

    args.approved.parent.mkdir(parents=True, exist_ok=True)
    training = run([
        sys.executable, "-m", "email_analyzer.train_evidence_ml",
        str(args.training_manifest), str(args.candidate), "--text-bins", str(args.text_bins),
        "--model-id", args.model_id,
    ])
    status["training_returncode"] = training.returncode
    status["trained"] = training.returncode == 0 and args.candidate.is_file()
    if not status["trained"]:
        status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        raise SystemExit(training.returncode or 2)

    evaluation = run([
        sys.executable, "-m", "email_analyzer.evaluate_evidence_ml",
        str(args.candidate), str(args.external_manifest), str(external_report),
        "--min-rows", str(args.external_min_rows), "--min-auc", str(args.external_min_auc),
        "--max-fpr", str(args.external_max_fpr), "--min-recall", str(args.external_min_recall),
    ])
    status["external_returncode"] = evaluation.returncode
    # Failed evaluation can leave an older report untouched. Never use it to
    # report this run's gate status (or let malformed stale JSON mask failure).
    if evaluation.returncode == 0 and external_report.is_file():
        report = json.loads(external_report.read_text(encoding="utf-8"))
        status["external_gate_passed"] = bool(report.get("promotion_allowed"))
    if status["external_gate_passed"] and evaluation.returncode == 0:
        shutil.copy2(args.candidate, args.approved)
        status["approved"] = True
        status["approved_path"] = str(args.approved)
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(status, ensure_ascii=False, indent=2))
    if not status["approved"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
