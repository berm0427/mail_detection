"""Measure semantic-model stability without touching the external audit set."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler


def metrics(y, p):
    prediction = p >= .5
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {"auc": float(roc_auc_score(y, p)), "accuracy": float((prediction == y).mean()),
            "fpr": float(fp / max(fp + tn, 1)), "recall": float(tp / max(tp + fn, 1))}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("manifest", type=Path)
    parser.add_argument("cache", type=Path); parser.add_argument("output", type=Path)
    parser.add_argument("--regularization-c", type=float, default=.1)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    y = np.asarray([int(row["label"]) for row in rows]); splits = np.asarray([row["split"] for row in rows])
    x = np.load(args.cache, allow_pickle=False)["embeddings"]
    train_indices = np.flatnonzero(splits == "train"); validation = splits == "validation"; test = splits == "test"
    trials = []
    for size in (1000, 2000, 4000, 8000):
        per_label = size // 2
        for seed in (11, 23, 37, 53, 71):
            rng = np.random.default_rng(seed)
            selected = np.concatenate([
                rng.choice(train_indices[y[train_indices] == label], per_label, replace=False)
                for label in (0, 1)
            ])
            scaler = StandardScaler().fit(x[selected]); transformed = scaler.transform(x)
            model = LogisticRegression(C=args.regularization_c, max_iter=3000, class_weight="balanced",
                                       random_state=seed, solver="liblinear")
            model.fit(transformed[selected], y[selected])
            trials.append({"train_rows": size, "seed": seed,
                           "validation": metrics(y[validation], model.predict_proba(transformed[validation])[:, 1]),
                           "test": metrics(y[test], model.predict_proba(transformed[test])[:, 1])})
    summary = {}
    for size in (1000, 2000, 4000, 8000):
        group = [trial for trial in trials if trial["train_rows"] == size]
        summary[str(size)] = {}
        for split in ("validation", "test"):
            summary[str(size)][split] = {}
            for name in ("auc", "accuracy", "fpr", "recall"):
                values = np.asarray([trial[split][name] for trial in group])
                summary[str(size)][split][name] = {"mean": float(values.mean()), "std": float(values.std()),
                                                    "min": float(values.min()), "max": float(values.max())}
    report = {"external_data_used": False, "regularization_c": args.regularization_c,
              "seeds": [11, 23, 37, 53, 71], "trials": trials, "summary": summary}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
