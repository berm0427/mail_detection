"""Evaluate candidate semantic/verdict models on the held-out eight emails.

The script reuses the latest production structural observations but recomputes
the semantic score from the original EML.  It never edits engine_config.json or
marks a candidate as promoted.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from email import policy
from email.parser import BytesParser
import json
from pathlib import Path
import re
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.engines.semantic_ml import SemanticMLEngine, preload_semantic_encoder
from email_analyzer.ml_verdict import analyze_ml_verdict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("semantic_artifact", type=Path)
    parser.add_argument("verdict_artifact", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--gui-report", type=Path,
                        default=PROJECT_ROOT / "analysis_result/ml-verdict-v4/gui/gui_report.json")
    parser.add_argument("--manifest", type=Path,
                        default=PROJECT_ROOT / "mail_body/test_data/user_real8_manifest.jsonl")
    args = parser.parse_args()
    semantic_artifact = args.semantic_artifact.resolve()
    verdict_artifact = args.verdict_artifact.resolve()
    preload_semantic_encoder(semantic_artifact)
    semantic_engine = SemanticMLEngine(semantic_artifact)
    manifest_rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines()
                     if line.strip()]
    report_rows = json.loads(args.gui_report.read_text(encoding="utf-8"))
    sessions: dict[str, Path] = {}
    for row in report_rows:
        match = re.search(r"세션 경로:\s*([^\r\n]+)", row.get("summary", ""))
        if not match:
            raise ValueError(f"GUI report has no session path for {row.get('id')}")
        sessions[row["id"]] = (PROJECT_ROOT / match.group(1).strip()).resolve()
    output_rows = []
    for row in manifest_rows:
        email_path = (args.manifest.resolve().parent / row["eml"]).resolve()
        message = BytesParser(policy=policy.default).parsebytes(email_path.read_bytes())
        semantic = asdict(semantic_engine.analyze(message))
        if semantic.get("status") != "ok":
            raise RuntimeError(f"semantic inference failed for {row['id']}: {semantic}")
        result_path = sessions[row["id"]] / "final_analysis_result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result.setdefault("engine_results", {})["semantic_ml"] = semantic
        verdict = analyze_ml_verdict(result, verdict_artifact, require_promoted=False)
        output_rows.append({
            "id": row["id"], "label": int(row["label"]), "eml": str(email_path),
            "semantic_score": semantic["score"], "verdict_score": verdict["score"],
            "prediction": verdict["prediction"],
            "correct": verdict["prediction"] == int(row["label"]),
            "structural_result": str(result_path),
        })
        print(f"{row['id']}: label={row['label']} semantic={semantic['score']:.3f} "
              f"verdict={verdict['score']:.3f} prediction={verdict['prediction']}", flush=True)
    labels = [row["label"] for row in output_rows]
    predictions = [row["prediction"] for row in output_rows]
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predictions))
    report = {
        "rows": len(output_rows), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "accuracy": (tn + tp) / len(output_rows),
        "used_for_training_or_selection": False,
        "semantic_artifact": str(semantic_artifact),
        "verdict_artifact": str(verdict_artifact),
        "predictions": output_rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("rows", "tn", "fp", "fn", "tp", "accuracy")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
