"""Leakage-controlled nested group CV for semantic and fusion classifiers.

The outer fold is untouched until final scoring.  Inside each outer training
partition, semantic regularization is selected by group CV and out-of-fold
semantic probabilities are generated for training the fusion classifier.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from scipy.stats import binomtest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.fusion_features import FEATURE_NAMES, fusion_feature_vector

C_GRID = (0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0, 3.0, 10.0)

ABLATIONS = {
    "without_semantic": ("semantic_score", "semantic_available", "signal:semantic_ml_corroborated"),
    "without_authentication": ("authentication_failure_count", "signal:authentication_failure"),
    "without_url_domain": ("display_target_mismatch_count", "official_claim_mismatch_count",
                            "signal:official_domain_confusable", "signal:unsafe_password_route"),
    "without_attachments": ("attachment_threat_count", "attachment_alert_count",
                            "attachment_failure_count", "signal:attachment_malware",
                            "signal:attachment_structure_alert"),
    "without_html_page": ("html_pair_score", "html_pair_available", "page_success_count",
                          "html_structure_signal_count", "signal:html_pair_ml_positive"),
    "without_legacy_rule": ("rule_score", "signal:legacy_rule_threshold"),
}


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def measure(labels, probabilities):
    labels = np.asarray(labels, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    predictions = probabilities >= 0.5
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "n": int(len(labels)),
        "auc": float(roc_auc_score(labels, probabilities)) if len(set(labels.tolist())) == 2 else None,
        "accuracy": float(accuracy_score(labels, predictions)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / max(fp + tn, 1)), "recall": float(tp / max(tp + fn, 1)),
    }


def semantic_fit_predict(embeddings, labels, train, test, c_value):
    scaler = StandardScaler().fit(embeddings[train])
    model = LogisticRegression(
        C=c_value, max_iter=3000, class_weight="balanced", random_state=42,
        solver="liblinear",
    ).fit(scaler.transform(embeddings[train]), labels[train])
    return model.predict_proba(scaler.transform(embeddings[test]))[:, 1]


def choose_c(embeddings, labels, groups, indices, folds):
    local_groups = groups[indices]
    splits = list(GroupKFold(n_splits=min(folds, len(set(local_groups)))).split(
        embeddings[indices], labels[indices], local_groups))
    trials = []
    for c_value in C_GRID:
        probabilities = np.zeros(len(indices), dtype=float)
        for train_local, holdout_local in splits:
            train, holdout = indices[train_local], indices[holdout_local]
            probabilities[holdout_local] = semantic_fit_predict(
                embeddings, labels, train, holdout, c_value)
        result = measure(labels[indices], probabilities)
        result["regularization_c"] = c_value
        trials.append(result)
    selected = max(trials, key=lambda row: (
        row["auc"], -row["fpr"], row["recall"], row["accuracy"], -row["regularization_c"]))
    return selected["regularization_c"], splits, trials


def with_semantic(analysis, score):
    result = copy.deepcopy(analysis)
    result.setdefault("engine_results", {})["semantic_ml"] = {
        "status": "ok", "score": float(score),
        "details": {"predicted_label": int(score >= 0.5)},
    }
    return result


def classifier_set():
    return {
        "logistic_regression": LogisticRegression(
            C=0.1, max_iter=3000, class_weight="balanced", random_state=42),
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
            random_state=42, n_jobs=-1),
    }


def zero_columns(matrix, names):
    result = matrix.copy()
    for name in names:
        result[:, FEATURE_NAMES.index(name)] = 0.0
    return result


def paired_error_test(labels, baseline, candidate):
    baseline_wrong = (np.asarray(baseline) >= 0.5) != labels
    candidate_wrong = (np.asarray(candidate) >= 0.5) != labels
    baseline_only_wrong = int(np.sum(baseline_wrong & ~candidate_wrong))
    candidate_only_wrong = int(np.sum(~baseline_wrong & candidate_wrong))
    discordant = baseline_only_wrong + candidate_only_wrong
    p_value = float(binomtest(min(baseline_only_wrong, candidate_only_wrong), discordant,
                              p=0.5).pvalue) if discordant else 1.0
    return {"baseline_only_wrong": baseline_only_wrong,
            "candidate_only_wrong": candidate_only_wrong,
            "discordant": discordant, "exact_mcnemar_p": p_value}


def group_bootstrap_delta(labels, groups, baseline, candidate, iterations=5000):
    rng = np.random.default_rng(42)
    unique = np.asarray(sorted(set(groups.tolist())))
    deltas = []
    for _ in range(iterations):
        sampled = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([np.flatnonzero(groups == group) for group in sampled])
        baseline_accuracy = np.mean((baseline[indices] >= 0.5) == labels[indices])
        candidate_accuracy = np.mean((candidate[indices] >= 0.5) == labels[indices])
        deltas.append(candidate_accuracy - baseline_accuracy)
    low, high = np.quantile(deltas, [0.025, 0.975])
    return {"iterations": iterations, "unit": "scenario_group",
            "accuracy_delta": float(np.mean((candidate >= 0.5) == labels) -
                                    np.mean((baseline >= 0.5) == labels)),
            "ci95": [float(low), float(high)]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("evidence_manifest", type=Path)
    parser.add_argument("embedding_cache", type=Path)
    parser.add_argument("--outer-folds", type=int, default=10)
    parser.add_argument("--inner-folds", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    training = read_jsonl(args.training_manifest.resolve())
    evidence = read_jsonl(args.evidence_manifest.resolve())
    cached = np.load(args.embedding_cache.resolve(), allow_pickle=False)
    embeddings = cached["embeddings"]
    if len(training) != len(embeddings):
        raise ValueError("embedding cache and training manifest size mismatch")
    embedding_index = {Path(row["eml"]).stem: index for index, row in enumerate(training)}
    try:
        order = np.asarray([embedding_index[Path(row["eml"]).stem] for row in evidence])
    except KeyError as error:
        raise ValueError(f"evidence row missing from embedding cache: {error}") from error
    embeddings = embeddings[order]
    labels = np.asarray([int(row["label"]) for row in evidence], dtype=int)
    groups = np.asarray([str(row["group_id"]) for row in evidence])
    if len(set(groups)) < args.outer_folds:
        raise ValueError("not enough scenario groups for outer folds")

    splitter = StratifiedGroupKFold(
        n_splits=args.outer_folds, shuffle=True, random_state=42)
    semantic_probability = np.zeros(len(labels), dtype=float)
    model_probability = {name: np.zeros(len(labels), dtype=float)
                         for name in ("structure_logistic", "fusion_logistic", "fusion_random_forest")}
    ablation_probability = {name: np.zeros(len(labels), dtype=float) for name in ABLATIONS}
    dropout_probability = {name: np.zeros(len(labels), dtype=float)
                           for name in ("semantic_engine_unavailable", "structure_engines_unavailable")}
    fold_reports = []
    for fold, (outer_train, outer_test) in enumerate(splitter.split(embeddings, labels, groups), 1):
        selected_c, inner_splits, trials = choose_c(
            embeddings, labels, groups, outer_train, args.inner_folds)
        train_semantic = np.zeros(len(outer_train), dtype=float)
        for train_local, holdout_local in inner_splits:
            train, holdout = outer_train[train_local], outer_train[holdout_local]
            train_semantic[holdout_local] = semantic_fit_predict(
                embeddings, labels, train, holdout, selected_c)
        test_semantic = semantic_fit_predict(
            embeddings, labels, outer_train, outer_test, selected_c)
        semantic_probability[outer_test] = test_semantic

        train_structure = np.asarray([
            fusion_feature_vector(evidence[index]["analysis"]) for index in outer_train])
        test_structure = np.asarray([
            fusion_feature_vector(evidence[index]["analysis"]) for index in outer_test])
        train_fusion = np.asarray([
            fusion_feature_vector(with_semantic(evidence[index]["analysis"], score))
            for index, score in zip(outer_train, train_semantic)])
        test_fusion = np.asarray([
            fusion_feature_vector(with_semantic(evidence[index]["analysis"], score))
            for index, score in zip(outer_test, test_semantic)])

        structure_model = classifier_set()["logistic_regression"].fit(
            train_structure, labels[outer_train])
        model_probability["structure_logistic"][outer_test] = \
            structure_model.predict_proba(test_structure)[:, 1]
        for name, model in classifier_set().items():
            model.fit(train_fusion, labels[outer_train])
            model_probability[f"fusion_{name.split('_')[0]}" if name == "logistic_regression"
                              else "fusion_random_forest"][outer_test] = \
                model.predict_proba(test_fusion)[:, 1]
        for name, removed in ABLATIONS.items():
            model = classifier_set()["logistic_regression"].fit(
                zero_columns(train_fusion, removed), labels[outer_train])
            ablation_probability[name][outer_test] = model.predict_proba(
                zero_columns(test_fusion, removed))[:, 1]
        full_model = classifier_set()["logistic_regression"].fit(
            train_fusion, labels[outer_train])
        dropout_probability["semantic_engine_unavailable"][outer_test] = full_model.predict_proba(
            zero_columns(test_fusion, ABLATIONS["without_semantic"]))[:, 1]
        structure_columns = tuple(name for name in FEATURE_NAMES
                                  if name not in {"semantic_score", "semantic_available"})
        dropout_probability["structure_engines_unavailable"][outer_test] = full_model.predict_proba(
            zero_columns(test_fusion, structure_columns))[:, 1]
        fold_reports.append({
            "fold": fold, "test_rows": int(len(outer_test)),
            "test_groups": sorted(set(groups[outer_test].tolist())),
            "selected_semantic_c": selected_c,
            "semantic": measure(labels[outer_test], test_semantic),
            "inner_selection_best": next(row for row in trials
                                         if row["regularization_c"] == selected_c),
        })
        print(f"[{fold}/{args.outer_folds}] groups={fold_reports[-1]['test_groups']} C={selected_c}", flush=True)

    semantic_prediction = semantic_probability >= 0.5
    structure_prediction = model_probability["structure_logistic"] >= 0.5
    disagreement = semantic_prediction != structure_prediction
    report = {
        "protocol": "nested_stratified_group_cv_with_oof_stacking",
        "rows": len(labels), "groups": len(set(groups)),
        "outer_folds": args.outer_folds, "inner_folds": args.inner_folds,
        "feature_names": list(FEATURE_NAMES),
        "semantic_only": measure(labels, semantic_probability),
        "models": {name: measure(labels, probability)
                   for name, probability in model_probability.items()},
        "ablations": {name: measure(labels, probability)
                      for name, probability in ablation_probability.items()},
        "engine_dropout": {name: measure(labels, probability)
                           for name, probability in dropout_probability.items()},
        "natural_conflict_subset": {
            "n": int(disagreement.sum()),
            "semantic_only": measure(labels[disagreement], semantic_probability[disagreement])
                if disagreement.any() else None,
            "structure_logistic": measure(labels[disagreement],
                                            model_probability["structure_logistic"][disagreement])
                if disagreement.any() else None,
            "fusion_logistic": measure(labels[disagreement],
                                         model_probability["fusion_logistic"][disagreement])
                if disagreement.any() else None,
        },
        "paired_tests": {
            name: {
                "mcnemar": paired_error_test(labels, semantic_probability, probability),
                "group_bootstrap": group_bootstrap_delta(
                    labels, groups, semantic_probability, probability),
            }
            for name, probability in model_probability.items() if name.startswith("fusion_")
        },
        "folds": fold_reports,
        "limitations": [
            "All rows are synthetic; this does not establish real-world performance.",
            "Only 15 scenario groups are available, so several outer folds contain one scenario group.",
            "The eight real emails remain a small audit set and are not used for fitting.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "semantic_only": report["semantic_only"],
                      "models": report["models"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
