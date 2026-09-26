"""Inference for an experimental learned fusion artifact."""

from __future__ import annotations

import json
import math
from pathlib import Path

from email_analyzer.fusion_features import FEATURE_NAMES, fusion_feature_vector


def analyze_learned_fusion(result: dict, artifact_path) -> dict:
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    if artifact.get("feature_names") != list(FEATURE_NAMES):
        raise ValueError("learned fusion feature schema mismatch")
    vector = fusion_feature_vector(result)
    coefficients = artifact["coef"]
    if len(vector) != len(coefficients):
        raise ValueError("learned fusion vector size mismatch")
    logit = sum(value * weight for value, weight in zip(vector, coefficients)) + float(artifact["intercept"])
    score = 1 / (1 + math.exp(-logit)) if logit >= 0 else math.exp(logit) / (1 + math.exp(logit))
    threshold = float(artifact.get("decision_threshold", 0.5))
    return {
        "model_id": artifact["model_id"], "experimental": True,
        "affects_production_verdict": False, "score": score,
        "prediction": int(score >= threshold), "decision_threshold": threshold,
    }
