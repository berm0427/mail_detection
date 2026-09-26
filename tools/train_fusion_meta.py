"""Train and compare Logistic Regression and Random Forest fusion baselines."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.fusion_features import FEATURE_NAMES, fusion_feature_vector


def load_rows(manifest: Path):
    rows = []
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip(): continue
        row = json.loads(line)
        if row.get("label") not in (0, 1): raise ValueError(f"invalid label at row {line_number}")
        analysis = row.get("analysis")
        if analysis is None:
            path = Path(row["analysis_result"])
            if not path.is_absolute(): path = (manifest.parent / path).resolve()
            analysis = json.loads(path.read_text(encoding="utf-8"))
        rows.append({
            "id": row.get("id", str(line_number)), "label": int(row["label"]),
            "group": str(row.get("group_id") or row.get("id") or line_number),
            "split": str(row.get("split") or "unspecified"), "analysis": analysis,
        })
    return rows


def metrics(labels, probabilities, threshold=0.5):
    labels = np.asarray(labels, dtype=int); probabilities = np.asarray(probabilities, dtype=float)
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    auc = float(roc_auc_score(labels, probabilities)) if len(set(labels.tolist())) == 2 else None
    return {
        "n": int(len(labels)), "auc": auc,
        "accuracy": float(accuracy_score(labels, predictions)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
    }


def models():
    return {
        "logistic_regression": LogisticRegression(
            C=0.1, max_iter=3000, class_weight="balanced", random_state=42,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
            random_state=42, n_jobs=-1,
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--folds", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = load_rows(args.manifest.resolve())
    x = np.asarray([fusion_feature_vector(row["analysis"]) for row in rows], dtype=float)
    y = np.asarray([row["label"] for row in rows], dtype=int)
    groups = np.asarray([row["group"] for row in rows])
    if len(set(groups)) < args.folds: raise ValueError("not enough independent groups for requested folds")
    splitter = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=42)
    report = {"rows": len(rows), "groups": len(set(groups)), "folds": args.folds,
              "feature_names": list(FEATURE_NAMES), "models": {}}
    for name, prototype in models().items():
        probabilities = np.zeros(len(rows), dtype=float); fold_rows = []
        for fold, (train, holdout) in enumerate(splitter.split(x, y, groups)):
            model = prototype.__class__(**prototype.get_params())
            model.fit(x[train], y[train])
            fold_probability = model.predict_proba(x[holdout])[:, 1]
            probabilities[holdout] = fold_probability
            fold_result = metrics(y[holdout], fold_probability)
            fold_result.update({"fold": fold, "groups": sorted(set(groups[holdout].tolist()))})
            fold_rows.append(fold_result)
        report["models"][name] = {"out_of_fold": metrics(y, probabilities), "folds": fold_rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "rows": len(rows),
                      "groups": len(set(groups)), "folds": args.folds}, ensure_ascii=False))


if __name__ == "__main__":
    main()
