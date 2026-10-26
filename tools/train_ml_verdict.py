"""Nested group CV and final fit for the ML verdict model (feature schema v2).

Evaluation follows ``nested_fusion_group_cv.py``: outer scenario-group folds
are untouched until scoring, and the verdict model is trained on inner
out-of-fold semantic probabilities.  After evaluation one model is fitted on
all rows (semantic OOF from group folds over the whole corpus) and written as a
candidate artifact.  The artifact is never promoted automatically.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedGroupKFold

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for path in (PROJECT_ROOT, PROJECT_ROOT / "tools"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from email_analyzer.ml_verdict_features import FEATURE_NAMES, SCHEMA_VERSION, ml_verdict_feature_vector
from nested_fusion_group_cv import (choose_c, group_bootstrap_delta, measure, paired_error_test,
                                    read_jsonl, semantic_fit_predict, with_semantic)

ABLATIONS = {
    "without_semantic": ("semantic_score", "semantic_available"),
    "without_sender_relations": ("from_reply_mismatch", "from_return_path_mismatch"),
    "without_link_relations": ("external_link_domain_present", "display_target_mismatch_count",
                               "official_claim_mismatch_count"),
}


def verdict_model():
    return LogisticRegression(C=0.1, max_iter=3000, class_weight="balanced", random_state=42)


def matrix(evidence, indices, semantic):
    return np.asarray([ml_verdict_feature_vector(with_semantic(evidence[i]["analysis"], s))
                       for i, s in zip(indices, semantic)])


def zero(features, names):
    result = features.copy()
    for name in names:
        result[:, FEATURE_NAMES.index(name)] = 0.0
    return result


def oof_semantic(embeddings, labels, groups, indices, folds):
    c_value, splits, _ = choose_c(embeddings, labels, groups, indices, folds)
    scores = np.zeros(len(indices), dtype=float)
    for train_local, holdout_local in splits:
        scores[holdout_local] = semantic_fit_predict(
            embeddings, labels, indices[train_local], indices[holdout_local], c_value)
    return c_value, scores


def with_pr_auc(labels, probabilities):
    report = measure(labels, probabilities)
    report["pr_auc"] = float(average_precision_score(labels, probabilities))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("evidence_manifest", type=Path)
    parser.add_argument("embedding_cache", type=Path)
    parser.add_argument("--outer-folds", type=int, default=10)
    parser.add_argument("--inner-folds", type=int, default=5)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()

    training = read_jsonl(args.training_manifest.resolve())
    evidence = read_jsonl(args.evidence_manifest.resolve())
    if any(row["analysis"].get("verdict_status") == "error" for row in evidence):
        raise ValueError("evidence manifest contains failed analyses")
    embeddings = np.load(args.embedding_cache.resolve(), allow_pickle=False)["embeddings"]
    if len(training) != len(embeddings):
        raise ValueError("embedding cache and training manifest size mismatch")
    position = {Path(row["eml"]).stem: index for index, row in enumerate(training)}
    embeddings = embeddings[np.asarray([position[Path(row["eml"]).stem] for row in evidence])]
    labels = np.asarray([int(row["label"]) for row in evidence], dtype=int)
    groups = np.asarray([str(row["group_id"]) for row in evidence])

    semantic_probability = np.zeros(len(labels))
    verdict_probability = np.zeros(len(labels))
    ablation_probability = {name: np.zeros(len(labels)) for name in ABLATIONS}
    folds = []
    splitter = StratifiedGroupKFold(n_splits=args.outer_folds, shuffle=True, random_state=42)
    for fold, (outer_train, outer_test) in enumerate(splitter.split(embeddings, labels, groups), 1):
        c_value, train_semantic = oof_semantic(embeddings, labels, groups, outer_train, args.inner_folds)
        test_semantic = semantic_fit_predict(embeddings, labels, outer_train, outer_test, c_value)
        semantic_probability[outer_test] = test_semantic
        train_x = matrix(evidence, outer_train, train_semantic)
        test_x = matrix(evidence, outer_test, test_semantic)
        model = verdict_model().fit(train_x, labels[outer_train])
        verdict_probability[outer_test] = model.predict_proba(test_x)[:, 1]
        for name, removed in ABLATIONS.items():
            ablated = verdict_model().fit(zero(train_x, removed), labels[outer_train])
            ablation_probability[name][outer_test] = ablated.predict_proba(zero(test_x, removed))[:, 1]
        folds.append({"fold": fold, "test_groups": sorted(set(groups[outer_test].tolist())),
                      "selected_semantic_c": c_value,
                      "coef": dict(zip(FEATURE_NAMES, model.coef_[0].round(6).tolist())),
                      "ml_verdict": with_pr_auc(labels[outer_test], verdict_probability[outer_test])
                      if len(set(labels[outer_test])) == 2 else measure(labels[outer_test], verdict_probability[outer_test])})
        print(f"[{fold}/{args.outer_folds}] groups={folds[-1]['test_groups']} C={c_value}", flush=True)

    # Final model on every row; semantic inputs remain out-of-fold.
    all_rows = np.arange(len(labels))
    final_c, final_semantic = oof_semantic(embeddings, labels, groups, all_rows, args.inner_folds)
    final_x = matrix(evidence, all_rows, final_semantic)
    final = verdict_model().fit(final_x, labels)
    variance = final_x.std(axis=0)
    evidence_sha = hashlib.sha256(args.evidence_manifest.read_bytes()).hexdigest()
    artifact = {
        "model_id": "dise-ml-verdict-v2",
        "feature_schema": SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "coef": final.coef_[0].tolist(),
        "intercept": float(final.intercept_[0]),
        "decision_threshold": 0.5,
        "promoted_to_gui": False,
        "training_rows": int(len(labels)),
        "training_groups": int(len(set(groups))),
        "semantic_input": {"source": "group_oof_logistic_on_cached_embeddings", "regularization_c": final_c},
        "untrained_features": [name for name, value in zip(FEATURE_NAMES, variance) if value == 0],
        "evidence_manifest_sha256": evidence_sha,
        "limitations": [
            "All training rows are synthetic and use reserved .example domains.",
            "Features listed in untrained_features had no variation and carry no learned weight.",
        ],
    }
    report = {
        "protocol": "nested_stratified_group_cv_with_oof_semantic",
        "feature_schema": SCHEMA_VERSION, "feature_names": list(FEATURE_NAMES),
        "rows": int(len(labels)), "groups": int(len(set(groups))),
        "evidence_manifest_sha256": evidence_sha,
        "semantic_only": with_pr_auc(labels, semantic_probability),
        "ml_verdict": with_pr_auc(labels, verdict_probability),
        "ablations": {name: with_pr_auc(labels, p) for name, p in ablation_probability.items()},
        "paired_vs_semantic": {
            "mcnemar": paired_error_test(labels, semantic_probability, verdict_probability),
            "group_bootstrap": group_bootstrap_delta(labels, groups, semantic_probability, verdict_probability),
        },
        "feature_coverage": {name: {"rows_nonzero": int((final_x[:, i] != 0).sum()),
                                    "phishing_nonzero": int(((final_x[:, i] != 0) & (labels == 1)).sum()),
                                    "normal_nonzero": int(((final_x[:, i] != 0) & (labels == 0)).sum())}
                             for i, name in enumerate(FEATURE_NAMES)},
        "final_model": {k: artifact[k] for k in ("coef", "intercept", "untrained_features", "semantic_input")},
        "folds": folds,
    }
    for path, payload in ((args.metrics, report), (args.artifact, artifact)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"semantic_only": report["semantic_only"], "ml_verdict": report["ml_verdict"],
                      "final_coef": dict(zip(FEATURE_NAMES, np.round(final.coef_[0], 4).tolist())),
                      "intercept": round(float(final.intercept_[0]), 4),
                      "untrained_features": artifact["untrained_features"]}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
