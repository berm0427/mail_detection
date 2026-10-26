"""Inference for the ML verdict artifact (feature schema v2)."""

from __future__ import annotations

import json
import math
from pathlib import Path

from email_analyzer.ml_verdict_features import FEATURE_NAMES, SCHEMA_VERSION, ml_verdict_feature_dict


def analyze_ml_verdict(result: dict, artifact_path) -> dict:
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    if artifact.get("feature_schema") != SCHEMA_VERSION or artifact.get("feature_names") != list(FEATURE_NAMES):
        raise ValueError("ML verdict feature schema mismatch")
    coefficients = artifact["coef"]
    if len(coefficients) != len(FEATURE_NAMES):
        raise ValueError("ML verdict coefficient size mismatch")
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
