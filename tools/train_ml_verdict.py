"""Nested group CV and matched final fits for the ML verdict model (feature schema v4).

Evaluation follows ``nested_fusion_group_cv.py``: outer scenario-group folds
are untouched until scoring, and the verdict model is trained on inner
out-of-fold semantic probabilities.  After evaluation the semantic
regularization is selected by group CV over the whole corpus, the verdict
model is fitted on the resulting OOF semantic probabilities, and the GUI
semantic model is fitted on every cached embedding with the same C.  Both
candidate artifacts carry matching provenance and are never promoted
automatically.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for path in (PROJECT_ROOT, PROJECT_ROOT / "tools"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from email_analyzer.ml_verdict_features import FEATURE_NAMES, SCHEMA_VERSION, ml_verdict_feature_vector
from nested_fusion_group_cv import (choose_c, group_bootstrap_delta, measure, paired_error_test,
                                    semantic_fit_predict, with_semantic)

VERDICT_MODEL_ID = "dise-ml-verdict-v3"
SEMANTIC_SCHEMA_VERSION = 1
SEMANTIC_SELECTION = "group_oof_selected_full_fit"
SEMANTIC_SOURCE = "group_oof_logistic_on_cached_embeddings"

ABLATIONS = {
    "without_semantic": ("semantic_score", "semantic_available"),
    "without_sender_relations": ("from_reply_mismatch", "from_return_path_mismatch"),
    "without_link_relations": ("external_link_domain_present", "display_target_mismatch_count",
                               "official_claim_mismatch_count"),
}


def verdict_model():
    return LogisticRegression(C=0.1, max_iter=3000, class_weight="balanced", random_state=42)


def fit_semantic(embeddings, labels, c_value):
    """Full-data counterpart of ``semantic_fit_predict``; settings must stay identical."""
    scaler = StandardScaler().fit(embeddings)
    model = LogisticRegression(
        C=c_value, max_iter=3000, class_weight="balanced", random_state=42,
        solver="liblinear",
    ).fit(scaler.transform(embeddings), labels)
    return scaler, model


def matrix(evidence, indices, semantic):
    if len(indices) != len(semantic):
        raise ValueError("semantic probability and feature row counts differ")
    result = np.asarray([ml_verdict_feature_vector(with_semantic(evidence[i]["analysis"], s))
                         for i, s in zip(indices, semantic)], dtype=float)
    if result.shape != (len(indices), len(FEATURE_NAMES)) or not np.isfinite(result).all():
        raise ValueError("invalid verdict feature matrix")
    return result


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
    return float(c_value), scores


def with_pr_auc(labels, probabilities):
    report = measure(labels, probabilities)
    report["pr_auc"] = float(average_precision_score(labels, probabilities))
    return report


# ---------------------------------------------------------------- input checks

def read_manifest(path):
    """Parse and hash the same bytes so the recorded SHA-256 matches the data used."""
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"manifest must contain nonempty JSON object rows: {path}")
    return rows, hashlib.sha256(raw).hexdigest()


def stem_positions(rows, name):
    positions = {}
    for index, row in enumerate(rows):
        eml = row.get("eml")
        stem = Path(eml).stem if isinstance(eml, str) else ""
        if not stem:
            raise ValueError(f"{name} row {index}: missing or empty eml")
        if stem in positions:
            raise ValueError(f"{name}: duplicate eml stem {stem!r}")
        positions[stem] = index
    return positions


def validate_evidence_rows(evidence):
    for index, row in enumerate(evidence):
        if not isinstance(row.get("analysis"), dict):
            raise ValueError(f"evidence row {index}: missing analysis object")
        if row["analysis"].get("verdict_status") == "error":
            raise ValueError("evidence manifest contains failed analyses")
        label = row.get("label")
        if isinstance(label, bool) or label not in (0, 1, "0", "1"):
            raise ValueError(f"evidence row {index}: label must be 0 or 1")
        group = row.get("group_id")
        if not isinstance(group, (str, int)) or isinstance(group, bool) or not str(group).strip():
            raise ValueError(f"evidence row {index}: missing or invalid group_id")


def evidence_order(training, evidence):
    """Map every evidence row to exactly one cache row and check label agreement."""
    training_positions = stem_positions(training, "training manifest")
    evidence_positions = stem_positions(evidence, "evidence manifest")
    missing_evidence = sorted(set(training_positions) - set(evidence_positions))
    missing_training = sorted(set(evidence_positions) - set(training_positions))
    if missing_evidence or missing_training:
        raise ValueError("training/evidence stem mapping is not one-to-one: "
                         f"missing evidence={missing_evidence[:10]} ({len(missing_evidence)}), "
                         f"missing training={missing_training[:10]} ({len(missing_training)})")
    order = np.asarray([training_positions[Path(row["eml"]).stem] for row in evidence], dtype=int)
    for evidence_row, cache_index in zip(evidence, order):
        training_label = training[cache_index].get("label")
        if training_label is not None and str(training_label) != str(evidence_row["label"]):
            raise ValueError(f"label disagreement for {Path(evidence_row['eml']).stem!r}")
    return order


def load_embeddings(path, expected_rows):
    with np.load(path, allow_pickle=False) as cached:
        if "embeddings" not in cached.files:
            raise ValueError("embedding cache has no embeddings array")
        embeddings = np.asarray(cached["embeddings"])
    if embeddings.ndim != 2 or embeddings.shape[1] == 0:
        raise ValueError("embeddings must be a nonempty two-dimensional matrix")
    if len(embeddings) != expected_rows:
        raise ValueError("embedding cache and training manifest size mismatch")
    if embeddings.dtype.kind not in "fiu" or not np.isfinite(embeddings).all():
        raise ValueError("embeddings must be finite real numbers")
    # GUI encodes with normalize_embeddings=True; the cache must match that space.
    norms = np.linalg.norm(embeddings.astype(np.float64), axis=1)
    if not np.allclose(norms, 1.0, rtol=1e-3, atol=1e-3):
        raise ValueError("embedding cache must contain L2-normalized embeddings")
    return embeddings


def require_both_labels(labels, indices, context):
    if set(labels[indices].tolist()) != {0, 1}:
        raise ValueError(f"{context} must contain both labels 0 and 1")


def validate_inner_partitions(embeddings, labels, groups, indices, folds, context):
    """Reproduce choose_c's GroupKFold so liblinear never sees a single-class fold."""
    require_both_labels(labels, indices, context)
    group_count = len(set(groups[indices].tolist()))
    if group_count < 2:
        raise ValueError(f"{context}: at least two groups are required")
    splitter = GroupKFold(n_splits=min(folds, group_count))
    for number, (train_local, _) in enumerate(
            splitter.split(embeddings[indices], labels[indices], groups[indices]), 1):
        require_both_labels(labels, indices[train_local], f"{context}, inner training fold {number}")


def validate_output_paths(outputs, inputs, model_dir):
    if len(set(outputs)) != len(outputs):
        raise ValueError("metrics, semantic artifact and verdict artifact paths must differ")
    for output in outputs:
        if output.exists() and not output.is_file():
            raise ValueError(f"output is not a regular file: {output}")
        if output == model_dir or model_dir in output.parents:
            raise ValueError(f"output would write into the embedding model directory: {output}")
        for source in inputs:
            if output == source or (output.exists() and output.samefile(source)):
                raise ValueError(f"output would overwrite an input: {output}")
    for index, output in enumerate(outputs):
        for other in outputs[index + 1:]:
            if output in other.parents or other in output.parents:
                raise ValueError("an output file cannot be another output's parent")
            if output.exists() and other.exists() and output.samefile(other):
                raise ValueError("output paths alias the same file")


# ---------------------------------------------------------------- atomic output

def stage_bytes(destination, content):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent, prefix=f".{destination.name}.",
                                         suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def write_json_bundle(items):
    """Stage every JSON first, then replace; roll back ordinary commit failures.

    Each Path.replace is atomic, but several files cannot form a crash-atomic
    transaction without a reader-aware pointer protocol.
    """
    # Serialization errors (e.g. NaN) surface here, before any file is touched.
    encoded = [(path, (json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
                .encode("utf-8")) for path, payload in items]
    staged, backups, replaced = {}, {}, []
    preserve_backups = False
    try:
        for path, content in encoded:
            path.parent.mkdir(parents=True, exist_ok=True)
            staged[path] = stage_bytes(path, content)
            backups[path] = stage_bytes(path, path.read_bytes()) if path.exists() else None
        for path, _ in encoded:
            staged[path].replace(path)
            replaced.append(path)
    except BaseException as error:
        rollback_errors = []
        for path in reversed(replaced):
            try:
                if backups[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    backups[path].replace(path)
            except OSError as rollback_error:
                rollback_errors.append(f"{path}: {rollback_error}")
        if rollback_errors:
            preserve_backups = True
            recovery = {str(path): str(backup) for path, backup in backups.items()
                        if backup is not None and backup.exists()}
            raise RuntimeError(f"output rollback failed: {rollback_errors}; "
                               f"recovery files: {recovery}") from error
        raise
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
        if not preserve_backups:
            for backup in backups.values():
                if backup is not None:
                    backup.unlink(missing_ok=True)


# ---------------------------------------------------------------- training

def cross_validate(evidence, embeddings, labels, groups, outer_splits, inner_folds):
    semantic_probability = np.zeros(len(labels))
    verdict_probability = np.zeros(len(labels))
    ablation_probability = {name: np.zeros(len(labels)) for name in ABLATIONS}
    folds = []
    for fold, (outer_train, outer_test) in enumerate(outer_splits, 1):
        c_value, train_semantic = oof_semantic(embeddings, labels, groups, outer_train, inner_folds)
        test_semantic = semantic_fit_predict(embeddings, labels, outer_train, outer_test, c_value)
        semantic_probability[outer_test] = test_semantic
        train_x = matrix(evidence, outer_train, train_semantic)
        test_x = matrix(evidence, outer_test, test_semantic)
        model = verdict_model().fit(train_x, labels[outer_train])
        verdict_probability[outer_test] = model.predict_proba(test_x)[:, 1]
        for name, removed in ABLATIONS.items():
            ablated = verdict_model().fit(zero(train_x, removed), labels[outer_train])
            ablation_probability[name][outer_test] = ablated.predict_proba(zero(test_x, removed))[:, 1]
        test_labels, test_probability = labels[outer_test], verdict_probability[outer_test]
        folds.append({"fold": fold, "test_groups": sorted(set(groups[outer_test].tolist())),
                      "selected_semantic_c": c_value,
                      "coef": dict(zip(FEATURE_NAMES, model.coef_[0].round(6).tolist())),
                      "ml_verdict": with_pr_auc(test_labels, test_probability)
                      if len(set(test_labels.tolist())) == 2 else measure(test_labels, test_probability)})
        print(f"[{fold}/{len(outer_splits)}] groups={folds[-1]['test_groups']} C={c_value}", flush=True)
    return semantic_probability, verdict_probability, ablation_probability, folds


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("evidence_manifest", type=Path)
    parser.add_argument("embedding_cache", type=Path)
    parser.add_argument("--outer-folds", type=int, default=10)
    parser.add_argument("--inner-folds", type=int, default=5)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--semantic-artifact", type=Path, required=True)
    parser.add_argument("--embedding-model", type=Path, required=True)
    parser.add_argument("--semantic-model-id", default="dise-multilingual-semantic-v4")
    args = parser.parse_args()
    if args.outer_folds < 2 or args.inner_folds < 2:
        parser.error("--outer-folds and --inner-folds must be at least 2")
    if not args.semantic_model_id.strip():
        parser.error("--semantic-model-id must not be empty")
    return args


def main():
    args = parse_args()
    training_path = args.training_manifest.resolve()
    evidence_path = args.evidence_manifest.resolve()
    cache_path = args.embedding_cache.resolve()
    model_dir = args.embedding_model.resolve()
    metrics_path = args.metrics.resolve()
    verdict_path = args.artifact.resolve()
    semantic_path = args.semantic_artifact.resolve()

    # Every check runs before training so a bad input never touches existing outputs.
    if not model_dir.is_dir():
        raise ValueError(f"embedding model directory is missing: {model_dir}")
    validate_output_paths((metrics_path, verdict_path, semantic_path),
                          (training_path, evidence_path, cache_path), model_dir)
    training, training_sha = read_manifest(training_path)
    evidence, evidence_sha = read_manifest(evidence_path)
    validate_evidence_rows(evidence)
    order = evidence_order(training, evidence)
    embeddings = load_embeddings(cache_path, len(training))[order]
    labels = np.asarray([int(row["label"]) for row in evidence], dtype=int)
    groups = np.asarray([str(row["group_id"]) for row in evidence])
    all_rows = np.arange(len(labels))
    group_count = len(set(groups.tolist()))
    require_both_labels(labels, all_rows, "complete corpus")
    if group_count < args.outer_folds:
        raise ValueError("not enough scenario groups for outer folds")

    splitter = StratifiedGroupKFold(n_splits=args.outer_folds, shuffle=True, random_state=42)
    outer_splits = list(splitter.split(embeddings, labels, groups))
    validate_inner_partitions(embeddings, labels, groups, all_rows, args.inner_folds, "complete corpus")
    for fold, (outer_train, _) in enumerate(outer_splits, 1):
        validate_inner_partitions(embeddings, labels, groups, outer_train, args.inner_folds,
                                  f"outer training fold {fold}")

    semantic_probability, verdict_probability, ablation_probability, folds = cross_validate(
        evidence, embeddings, labels, groups, outer_splits, args.inner_folds)

    # Final verdict model: C chosen by group CV on every row, semantic inputs stay out-of-fold.
    final_c, final_semantic = oof_semantic(embeddings, labels, groups, all_rows, args.inner_folds)
    final_x = matrix(evidence, all_rows, final_semantic)
    final = verdict_model().fit(final_x, labels)
    variance = final_x.std(axis=0)
    untrained = variance == 0
    final_coef = final.coef_[0].copy()
    final_intercept = float(final.intercept_[0])
    # Constant features are not learned evidence.  Preserve every fitted
    # probability by absorbing their constant contribution into the intercept,
    # then publish an exact zero coefficient for auditability.
    if untrained.any():
        final_intercept += float(final_x[0, untrained] @ final_coef[untrained])
        final_coef[untrained] = 0.0
    coverage = {name: {"rows_nonzero": int((final_x[:, i] != 0).sum()),
                       "phishing_nonzero": int(((final_x[:, i] != 0) & (labels == 1)).sum()),
                       "normal_nonzero": int(((final_x[:, i] != 0) & (labels == 0)).sum())}
                for i, name in enumerate(FEATURE_NAMES)}

    # Serving generator: same C refit on every cached row (mapping is one-to-one).
    scaler, semantic_model = fit_semantic(embeddings, labels, final_c)
    if np.any(scaler.scale_ <= 0):
        raise ValueError("semantic scaler produced non-positive scale")
    semantic_artifact = {
        "model_id": args.semantic_model_id,
        "schema_version": SEMANTIC_SCHEMA_VERSION,
        "positive_class": "label_1",
        "embedding_dimensions": int(embeddings.shape[1]),
        "embedding_normalized": True,
        "embedding_model_path": str(model_dir),
        "decision_threshold": 0.5,
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "coef": semantic_model.coef_[0].tolist(),
        "intercept": float(semantic_model.intercept_[0]),
        "regularization_c": final_c,
        "manifest_sha256": training_sha,
        "training_rows": int(len(training)),
        "selection": SEMANTIC_SELECTION,
    }
    artifact = {
        "model_id": VERDICT_MODEL_ID,
        "feature_schema": SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "coef": final_coef.tolist(),
        "intercept": final_intercept,
        "decision_threshold": 0.5,
        "promoted_to_gui": False,
        "training_rows": int(len(labels)),
        "training_groups": int(group_count),
        "semantic_input": {"source": SEMANTIC_SOURCE,
                           **{key: semantic_artifact[key]
                              for key in ("model_id", "regularization_c", "manifest_sha256")}},
        "untrained_features": [name for name, value in zip(FEATURE_NAMES, untrained) if value],
        "evidence_manifest_sha256": evidence_sha,
        "limitations": [
            "All training rows are synthetic and use reserved .example domains.",
            "Features listed in untrained_features had no variation and carry no learned weight.",
            "external_link_domain_present has no positive examples among normal training rows; "
            "its learned weight requires validation on labelled normal mail with external links.",
        ],
    }
    report = {
        "protocol": "nested_stratified_group_cv_with_oof_semantic",
        "feature_schema": SCHEMA_VERSION, "feature_names": list(FEATURE_NAMES),
        "rows": int(len(labels)), "groups": int(group_count),
        "outer_folds": args.outer_folds, "inner_folds": args.inner_folds,
        "evidence_manifest_sha256": evidence_sha,
        "semantic_only": with_pr_auc(labels, semantic_probability),
        "ml_verdict": with_pr_auc(labels, verdict_probability),
        "ablations": {name: with_pr_auc(labels, p) for name, p in ablation_probability.items()},
        "paired_vs_semantic": {
            "mcnemar": paired_error_test(labels, semantic_probability, verdict_probability),
            "group_bootstrap": group_bootstrap_delta(labels, groups, semantic_probability, verdict_probability),
        },
        "feature_coverage": coverage,
        "final_semantic_artifact": {**{key: semantic_artifact[key]
                                       for key in ("model_id", "regularization_c", "manifest_sha256",
                                                   "training_rows", "selection")},
                                    "promoted_to_gui": False},
        "final_model": {k: artifact[k] for k in ("model_id", "coef", "intercept", "untrained_features",
                                                 "semantic_input", "promoted_to_gui")},
        "folds": folds,
    }

    write_json_bundle(((semantic_path, semantic_artifact), (verdict_path, artifact), (metrics_path, report)))
    print(json.dumps({"semantic_only": report["semantic_only"], "ml_verdict": report["ml_verdict"],
                      "final_semantic_artifact": report["final_semantic_artifact"],
                      "final_coef": dict(zip(FEATURE_NAMES, np.round(final_coef, 4).tolist())),
                      "intercept": round(final_intercept, 4),
                      "untrained_features": artifact["untrained_features"]},
                     ensure_ascii=False, indent=1, allow_nan=False))


if __name__ == "__main__":
    main()
