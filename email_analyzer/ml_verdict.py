"""Inference for a provenance-matched ML verdict artifact."""

from __future__ import annotations

import json
import math
from pathlib import Path

from email_analyzer.ml_verdict_features import FEATURE_NAMES, SCHEMA_VERSION, ml_verdict_feature_dict


def analyze_ml_verdict(result: dict, artifact_path, require_promoted=False) -> dict:
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    if require_promoted and artifact.get("promoted_to_gui") is not True:
        raise ValueError("ML verdict artifact is not promoted to GUI")
    if artifact.get("feature_schema") != SCHEMA_VERSION or artifact.get("feature_names") != list(FEATURE_NAMES):
        raise ValueError("ML verdict feature schema mismatch")
    coefficients = artifact["coef"]
    if len(coefficients) != len(FEATURE_NAMES):
        raise ValueError("ML verdict coefficient size mismatch")
    expected = artifact.get("semantic_input") or {}
    actual = ((result.get("engine_results") or {}).get("semantic_ml") or {}).get("details") or {}
    for key in ("model_id", "manifest_sha256"):
        if expected.get(key) and actual.get(key) != expected[key]:
            raise ValueError(f"Semantic model provenance mismatch: {key}")
    if expected.get("regularization_c") is not None:
        try:
            same_c = math.isclose(float(actual.get("regularization_c")),
                                  float(expected["regularization_c"]), rel_tol=1e-12, abs_tol=1e-12)
        except (TypeError, ValueError):
            same_c = False
        if not same_c:
            raise ValueError("Semantic model provenance mismatch: regularization_c")
    features = ml_verdict_feature_dict(result)
    logit = float(artifact["intercept"]) + sum(
        features[name] * float(weight) for name, weight in zip(FEATURE_NAMES, coefficients))
    score = 1 / (1 + math.exp(-logit)) if logit >= 0 else math.exp(logit) / (1 + math.exp(logit))
    threshold = float(artifact.get("decision_threshold", 0.5))
    return {
        "model_id": artifact["model_id"], "score": score, "prediction": int(score >= threshold),
        "decision_threshold": threshold,
        "contributions": {name: features[name] * float(weight)
                          for name, weight in zip(FEATURE_NAMES, coefficients) if features[name] and weight},
        "untrained_features": list(artifact.get("untrained_features") or []),
    }
