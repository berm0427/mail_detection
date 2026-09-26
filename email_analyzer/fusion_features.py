"""Label-independent feature vector for learned evidence-fusion baselines."""

from __future__ import annotations

import math

SIGNAL_IDS = (
    "attachment_malware", "official_domain_confusable", "unsafe_password_route",
    "authentication_failure", "semantic_ml_corroborated", "html_pair_ml_positive",
    "razor_catalogue_match", "attachment_structure_alert", "legacy_rule_threshold",
)

FEATURE_NAMES = tuple(f"signal:{name}" for name in SIGNAL_IDS) + (
    "semantic_score", "semantic_available", "html_pair_score", "html_pair_available",
    "rule_score", "authentication_failure_count", "attachment_threat_count",
    "attachment_alert_count", "attachment_failure_count", "display_target_mismatch_count",
    "official_claim_mismatch_count", "page_success_count", "html_structure_signal_count",
    "unavailable_engine_count",
)


def _score(engine):
    value = (engine or {}).get("score")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return max(0.0, min(1.0, float(value))), 1.0
    return 0.0, 0.0


def fusion_feature_dict(result: dict) -> dict[str, float]:
    """Extract observations only; labels and final verdicts are never read."""
    decision = result.get("decision") or {}
    reflected = {item.get("id") for item in decision.get("signals") or []
                 if item.get("reflected")}
    features = {f"signal:{name}": float(name in reflected) for name in SIGNAL_IDS}
    engines = result.get("engine_results") or {}
    semantic_score, semantic_available = _score(engines.get("semantic_ml"))
    html_score, html_available = _score(engines.get("html_pair_ml"))
    rule = result.get("rule_result") or result
    auth = rule.get("auth_summary") or {}
    attachment = decision.get("attachment_scan") or {}
    links = result.get("link_evidence") or {}
    reference = result.get("reference_evidence") or {}
    pages = (result.get("page_analysis") or {}).get("pages") or []
    html_review = decision.get("html_review") or {}
    rule_score = rule.get("risk_score", result.get("risk_score", 0))
    features.update({
        "semantic_score": semantic_score,
        "semantic_available": semantic_available,
        "html_pair_score": html_score,
        "html_pair_available": html_available,
        "rule_score": max(0.0, min(1.0, float(rule_score or 0) / 100.0)),
        "authentication_failure_count": float(len(auth.get("failures") or [])),
        "attachment_threat_count": float(attachment.get("threats") or 0),
        "attachment_alert_count": float(attachment.get("alerts") or 0),
        "attachment_failure_count": float(attachment.get("failures") or 0),
        "display_target_mismatch_count": float(links.get("different_host_count") or 0),
        "official_claim_mismatch_count": float(reference.get("official_claim_mismatch_count") or 0),
        "page_success_count": float(sum(page.get("status") == "ok" for page in pages)),
        "html_structure_signal_count": float(len(html_review.get("signals") or [])),
        "unavailable_engine_count": float(len(decision.get("unavailable_engines") or [])),
    })
    return features


def fusion_feature_vector(result: dict) -> list[float]:
    features = fusion_feature_dict(result)
    return [features[name] for name in FEATURE_NAMES]
