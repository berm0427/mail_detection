"""Train a semantic email classifier while preserving publisher splits."""
from __future__ import annotations

import argparse
import hashlib
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
from sentence_transformers import SentenceTransformer

from email_analyzer.evidence_features import message_text


def measure(y: np.ndarray, probability: np.ndarray) -> dict:
    prediction = probability >= .5
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "auc": float(roc_auc_score(y, probability)),
            "accuracy": float((prediction == y).mean()), "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp), "fpr": float(fp / max(fp + tn, 1)),
            "recall": float(tp / max(tp + fn, 1))}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("embedding_model", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--model-id", default="dise-semantic-v1")
    args = parser.parse_args()
    base = args.manifest.resolve().parent
    rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = np.asarray([int(row["label"]) for row in rows])
    splits = np.asarray([row["split"] for row in rows])
    for split in ("train", "validation", "test"):
        if set(labels[splits == split]) != {0, 1}:
            raise ValueError(f"{split} must contain both labels")
    group_splits = {}
    for row in rows:
        group_splits.setdefault(str(row["group_id"]), set()).add(row["split"])
    if any(len(value) != 1 for value in group_splits.values()):
        raise ValueError("group leakage across splits")

    digest = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    model_fingerprint = hashlib.sha256(
        (str(args.embedding_model.resolve()) + '\n').encode('utf-8') +
        b''.join((args.embedding_model / name).read_bytes() if (args.embedding_model / name).is_file() else b''
                 for name in ('config.json', 'modules.json', 'tokenizer_config.json'))
    ).hexdigest()
    embeddings = None
    if args.cache and args.cache.is_file():
        cached = np.load(args.cache, allow_pickle=False)
        cached_fingerprint = str(cached['embedding_model_sha256']) if 'embedding_model_sha256' in cached else ''
        if str(cached["manifest_sha256"]) == digest and cached_fingerprint == model_fingerprint:
            embeddings = cached["embeddings"]
    if embeddings is None:
        texts = []
        for row in rows:
            path = Path(row["eml"]); path = path if path.is_absolute() else base / path
            message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
            texts.append(message_text(message))
        encoder = SentenceTransformer(str(args.embedding_model), device="cpu")
        embeddings = encoder.encode(texts, batch_size=args.batch_size, convert_to_numpy=True,
                                    normalize_embeddings=True, show_progress_bar=True)
        if args.cache:
            args.cache.parent.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(args.cache, embeddings=embeddings, manifest_sha256=np.asarray(digest),
                                embedding_model_sha256=np.asarray(model_fingerprint))

    train = splits == "train"; validation = splits == "validation"; test = splits == "test"
    scaler = StandardScaler().fit(embeddings[train])
    transformed = scaler.transform(embeddings)
    trials = []
    best = None
    for c_value in (.001, .003, .01, .03, .1, .3, 1.0, 3.0, 10.0):
        model = LogisticRegression(C=c_value, max_iter=3000, class_weight="balanced",
                                   random_state=42, solver="liblinear")
        model.fit(transformed[train], labels[train])
        probability = model.predict_proba(transformed[validation])[:, 1]
        result = measure(labels[validation], probability); result["regularization_c"] = c_value
        trials.append(result)
        key = (result["auc"], -result["fpr"], result["recall"], result["accuracy"], -c_value)
        if best is None or key > best[0]:
            best = (key, c_value)

    selected_c = best[1]
    selected = LogisticRegression(C=selected_c, max_iter=3000, class_weight="balanced",
                                  random_state=42, solver="liblinear")
    selected.fit(transformed[train], labels[train])
    validation_metrics = measure(labels[validation], selected.predict_proba(transformed[validation])[:, 1])
    test_metrics = measure(labels[test], selected.predict_proba(transformed[test])[:, 1])
    artifact = {"model_id": args.model_id, "schema_version": 1, "positive_class": "label_1",
                "embedding_dimensions": int(embeddings.shape[1]), "embedding_normalized": True,
                "embedding_model_path": str(args.embedding_model.resolve()), "decision_threshold": .5,
                "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(),
                "coef": selected.coef_[0].tolist(), "intercept": float(selected.intercept_[0]),
                "regularization_c": selected_c, "manifest_sha256": digest}
    report = {"rows": len(rows), "split_counts": {s: int((splits == s).sum()) for s in ("train", "validation", "test")},
              "selection_used_external_data": False, "trials": trials, "selected_c": selected_c,
              "validation": validation_metrics, "test": test_metrics,
              "limitations": "Synthetic internal performance does not establish real-world accuracy."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.output.with_suffix(".metrics.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
