"""Raw-observation feature vector for the ML verdict model.

Unlike ``fusion_features`` (v1), nothing here is read from the production
decision policy, the legacy rule score, or engine-availability counts.  Every
feature is an analyzer observation that is produced identically for synthetic
training mail and for live mail, so the training and serving definitions match.
"""

from __future__ import annotations

import math

from email_analyzer.html_review import html_review
from email_analyzer.observations import razor_match

SCHEMA_VERSION = "ml-verdict-features-v4"

FEATURE_NAMES = (
    "semantic_score",
    "semantic_available",
    "authentication_failure_count",
    "from_reply_mismatch",
    "from_return_path_mismatch",
    "external_link_domain_present",
    "display_target_mismatch_count",
    "official_claim_mismatch_count",
    "html_pair_score",
    "html_pair_available",
    "html_structure_signal_count",
    "attachment_threat_count",
    "attachment_alert_count",
    "razor_catalogue_match",
)


def _score(engine):
    value = (engine or {}).get("score")
    if (engine or {}).get("status") == "ok" and isinstance(value, (int, float)) \
            and not isinstance(value, bool) and math.isfinite(value):
        return max(0.0, min(1.0, float(value))), 1.0
    return 0.0, 0.0


def ml_verdict_feature_dict(result: dict) -> dict[str, float]:
    """Extract observations only; labels, verdicts and policy signals are never read."""
    engines = result.get("engine_results") or {}
    semantic_score, semantic_available = _score(engines.get("semantic_ml"))
    html_score, html_available = _score(engines.get("html_pair_ml"))
    auth = (result.get("rule_result") or {}).get("auth_summary") or {}
    links = result.get("link_evidence") or {}
    reference = result.get("reference_evidence") or {}
    scans = [(item.get("malware_scan") or {}) for item in result.get("attachments") or []]
    return {
        "semantic_score": semantic_score,
        "semantic_available": semantic_available,
        "authentication_failure_count": float(len(auth.get("failures") or [])),
        "from_reply_mismatch": float(reference.get("from_reply_relation") == "different_hosts"),
        "from_return_path_mismatch": float(reference.get("from_return_path_relation") == "different_hosts"),
        # Presence, not a count: the training corpus has at most one external
        # link domain per message, so larger counts were never observed.
        "external_link_domain_present": float(any(
            row.get("relationship") == "external_domain"
            for row in reference.get("domain_relationships") or [])),
        "display_target_mismatch_count": float(links.get("different_host_count") or 0),
        "official_claim_mismatch_count": float(reference.get("official_claim_mismatch_count") or 0),
        "html_pair_score": html_score,
        "html_pair_available": html_available,
        "html_structure_signal_count": float(len(html_review(result)["signals"])),
        "attachment_threat_count": float(sum(scan.get("status") == "threat_detected" for scan in scans)),
        "attachment_alert_count": float(sum(
            scan.get("status") in ("alert", "suspicious_structure") for scan in scans)),
        # Antivirus (above) and Razor outputs are inputs whose weight must be
        # learned from labels; with no variation in training they stay at zero.
        "razor_catalogue_match": float(razor_match(result)),
    }


def ml_verdict_feature_vector(result: dict) -> list[float]:
    features = ml_verdict_feature_dict(result)
    return [features[name] for name in FEATURE_NAMES]
