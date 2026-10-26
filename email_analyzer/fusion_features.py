"""Label-independent feature vector for learned evidence-fusion baselines.

The ``signal:*`` columns are presence indicators read directly from raw
observations (``email_analyzer.observations``), not from the production
decision's ``reflected`` flags.  Their weights are learned from labelled data;
where the data has no variation the learned coefficient stays zero.

Column names are kept for artifact compatibility.  Two columns describe policy
constructs that no longer exist and are always zero:
``signal:semantic_ml_corroborated`` and ``signal:legacy_rule_threshold``.

Results reported for the evidence-review-v7 era (models/fusion-nested-10fold-v1)
were produced with the earlier definition at commit 3431db0.
"""

from __future__ import annotations

import math

from email_analyzer.html_review import html_review
from email_analyzer.observations import attachment_scan_counts, collect_observations, unavailable_engines

SIGNAL_IDS = (
    "attachment_malware", "official_domain_confusable", "unsafe_password_route",
    "authentication_failure", "semantic_ml_corroborated", "html_pair_ml_positive",
    "razor_catalogue_match", "attachment_structure_alert", "legacy_rule_threshold",
)

# Column name -> observation id.  ``None`` marks a retired policy construct.
SIGNAL_SOURCES = {
    "attachment_malware": "attachment_antivirus_report",
    "official_domain_confusable": "official_domain_confusable",
    "unsafe_password_route": "unsafe_password_route",
    "authentication_failure": "authentication_failure",
    "semantic_ml_corroborated": None,
    "html_pair_ml_positive": "html_pair_ml_positive",
    "razor_catalogue_match": "razor_catalogue_match",
    "attachment_structure_alert": "attachment_structure_alert",
    "legacy_rule_threshold": None,
}

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
    """Extract observations only; labels, verdicts and policy flags are never read."""
    observed = {item["id"] for item in collect_observations(result)}
    features = {f"signal:{name}": float(SIGNAL_SOURCES[name] in observed) if SIGNAL_SOURCES[name] else 0.0
                for name in SIGNAL_IDS}
    engines = result.get("engine_results") or {}
    semantic_score, semantic_available = _score(engines.get("semantic_ml"))
    html_score, html_available = _score(engines.get("html_pair_ml"))
    rule = result.get("rule_result") or result
    auth = rule.get("auth_summary") or {}
    attachment = attachment_scan_counts(result)
    links = result.get("link_evidence") or {}
    reference = result.get("reference_evidence") or {}
    pages = (result.get("page_analysis") or {}).get("pages") or []
    rule_score = rule.get("risk_score", result.get("risk_score", 0))
    features.update({
        "semantic_score": semantic_score,
        "semantic_available": semantic_available,
        "html_pair_score": html_score,
        "html_pair_available": html_available,
        "rule_score": max(0.0, min(1.0, float(rule_score or 0) / 100.0)),
        "authentication_failure_count": float(len(auth.get("failures") or [])),
        "attachment_threat_count": float(attachment["threats"]),
        "attachment_alert_count": float(attachment["alerts"]),
        "attachment_failure_count": float(attachment["failures"]),
        "display_target_mismatch_count": float(links.get("different_host_count") or 0),
        "official_claim_mismatch_count": float(reference.get("official_claim_mismatch_count") or 0),
        "page_success_count": float(sum(page.get("status") == "ok" for page in pages)),
        "html_structure_signal_count": float(len(html_review(result)["signals"])),
        "unavailable_engine_count": float(len(unavailable_engines(result))),
    })
    return features


def fusion_feature_vector(result: dict) -> list[float]:
    features = fusion_feature_dict(result)
    return [features[name] for name in FEATURE_NAMES]
