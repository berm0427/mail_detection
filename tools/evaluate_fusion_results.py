"""Compare production and experimental fusion decisions on saved results.

The manifest is JSONL.  Each row must contain ``label`` (0/1) and either an
absolute ``analysis_result`` path or a path relative to the manifest file.
Missing results are reported and never counted as predictions.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.evidence_fusion import experimental_fusion
from email_analyzer.fusion_baselines import all_baselines


def _metrics(labels, predictions):
    tn = fp = fn = tp = 0
    for label, prediction in zip(labels, predictions):
        if label == 0 and prediction == 0: tn += 1
        elif label == 0 and prediction == 1: fp += 1
        elif label == 1 and prediction == 0: fn += 1
        elif label == 1 and prediction == 1: tp += 1
    return {
        "n": len(labels), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "accuracy": (tn + tp) / len(labels) if labels else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = args.manifest.resolve()
    rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    method_values = {}
    fusion_labels, fusion_predictions = [], []
    details, missing = [], []
    for row in rows:
        path = Path(row["analysis_result"])
        if not path.is_absolute(): path = (manifest.parent / path).resolve()
        if not path.is_file():
            missing.append(str(path)); continue
        result = json.loads(path.read_text(encoding="utf-8"))
        label = int(row["label"])
        baselines = all_baselines(result)
        legacy = baselines["production_policy"]["verdict"]
        fusion = result.get("experimental_fusion") or experimental_fusion(result)
        fusion_decisive = fusion["verdict"] in {"high_risk", "benign_supported"}
        for method, value in baselines.items():
            labels, predictions = method_values.setdefault(method, ([], []))
            labels.append(label); predictions.append(value["prediction"])
        if fusion_decisive:
            fusion_labels.append(label)
            fusion_predictions.append(int(fusion["verdict"] == "high_risk"))
        details.append({
            "id": row.get("id", path.stem), "label": label,
            "legacy_verdict": legacy, "baselines": baselines, "fusion": fusion,
            "fusion_decisive": fusion_decisive,
        })
    report = {
        "manifest": str(manifest), "available": len(details), "missing": missing,
        "baselines": {name: _metrics(labels, predictions)
                      for name, (labels, predictions) in method_values.items()},
        "experimental_decisive_only": _metrics(fusion_labels, fusion_predictions),
        "experimental_coverage": len(fusion_labels) / len(details) if details else 0.0,
        "details": details,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
