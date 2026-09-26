"""Deterministic fusion baselines for controlled comparison experiments."""

from __future__ import annotations

from email_analyzer.evidence_fusion import masses_from_result


def _observations(result):
    return [mass.discounted() for mass in masses_from_result(result)
            if mass.phishing > 0 or mass.benign > 0]


def simple_mean(result, threshold=0.5):
    """Mean discounted phishing support across available non-vacuous sources."""
    masses = _observations(result)
    score = sum(mass.phishing for mass in masses) / len(masses) if masses else 0.0
    return {"method": "simple_mean", "score": score,
            "prediction": int(bool(masses) and score >= threshold), "sources": len(masses)}


def reliability_weighted_mean(result, threshold=0.5):
    """Mean raw support weighted by the declared source reliability."""
    masses = [mass for mass in masses_from_result(result)
              if mass.phishing > 0 or mass.benign > 0]
    denominator = sum(mass.reliability for mass in masses)
    score = (sum(mass.phishing * mass.reliability for mass in masses) / denominator
             if denominator else 0.0)
    return {"method": "reliability_weighted_mean", "score": score,
            "prediction": int(bool(masses) and score >= threshold), "sources": len(masses)}


def majority_vote(result):
    """One vote per available source; ties and no evidence are non-phishing."""
    masses = _observations(result)
    phishing_votes = sum(mass.phishing > mass.benign for mass in masses)
    benign_votes = sum(mass.benign > mass.phishing for mass in masses)
    prediction = int(phishing_votes > benign_votes and phishing_votes > 0)
    return {"method": "majority_vote", "score": phishing_votes / len(masses) if masses else 0.0,
            "prediction": prediction, "sources": len(masses),
            "phishing_votes": phishing_votes, "benign_votes": benign_votes}


def production_policy(result):
    verdict = (result.get("decision") or {}).get("verdict", result.get("verdict"))
    return {"method": "production_policy", "score": None,
            "prediction": int(verdict in {"suspicious", "dangerous"}), "verdict": verdict}


def all_baselines(result):
    return {
        "production_policy": production_policy(result),
        "simple_mean": simple_mean(result),
        "reliability_weighted_mean": reliability_weighted_mean(result),
        "majority_vote": majority_vote(result),
    }
