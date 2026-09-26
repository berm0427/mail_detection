"""Experimental reliability-discounted evidence fusion.

This module is intentionally independent from the production decision policy.
It preserves three states for every source: phishing support, benign support,
and unresolved uncertainty.  Conflicting support is assigned to uncertainty
instead of being normalised into artificial confidence (Yager's rule).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


FUSION_VERSION = "rde-yager-v1"


@dataclass(frozen=True)
class EvidenceMass:
    source: str
    phishing: float = 0.0
    benign: float = 0.0
    uncertainty: float = 1.0
    reliability: float = 1.0
    observation: str = ""

    def discounted(self) -> "EvidenceMass":
        reliability = _bounded(self.reliability)
        phishing = reliability * _bounded(self.phishing)
        benign = reliability * _bounded(self.benign)
        uncertainty = 1.0 - phishing - benign
        return EvidenceMass(
            source=self.source,
            phishing=phishing,
            benign=benign,
            uncertainty=max(0.0, uncertainty),
            reliability=reliability,
            observation=self.observation,
        )


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalise(mass: EvidenceMass) -> EvidenceMass:
    values = [max(0.0, mass.phishing), max(0.0, mass.benign), max(0.0, mass.uncertainty)]
    total = sum(values)
    if total <= 0:
        values = [0.0, 0.0, 1.0]
        total = 1.0
    return EvidenceMass(
        source=mass.source,
        phishing=values[0] / total,
        benign=values[1] / total,
        uncertainty=values[2] / total,
        reliability=_bounded(mass.reliability),
        observation=mass.observation,
    )


def combine_pair(left: EvidenceMass, right: EvidenceMass) -> tuple[EvidenceMass, float]:
    """Combine two discounted masses and return (combined, pair conflict)."""
    left = _normalise(left)
    right = _normalise(right)
    conflict = left.phishing * right.benign + left.benign * right.phishing
    combined = EvidenceMass(
        source=f"{left.source}+{right.source}",
        phishing=(left.phishing * right.phishing
                  + left.phishing * right.uncertainty
                  + left.uncertainty * right.phishing),
        benign=(left.benign * right.benign
                + left.benign * right.uncertainty
                + left.uncertainty * right.benign),
        uncertainty=left.uncertainty * right.uncertainty + conflict,
        reliability=1.0,
        observation="Yager conflict-to-uncertainty combination",
    )
    return _normalise(combined), conflict


def fuse_masses(masses: Iterable[EvidenceMass]) -> dict:
    discounted = sorted(
        (_normalise(mass.discounted()) for mass in masses),
        key=lambda mass: mass.source,
    )

    # Unnormalised conjunctive accumulation is associative.  Empty-set mass is
    # retained until every source has been combined, then moved to uncertainty
    # once.  The result therefore does not depend on engine execution order.
    phishing = frozenset({"phishing"})
    benign = frozenset({"benign"})
    frame = frozenset({"phishing", "benign"})
    focal = {frame: 1.0}
    conflicts = []
    for mass in discounted:
        incoming = {
            phishing: mass.phishing,
            benign: mass.benign,
            frame: mass.uncertainty,
        }
        updated = {}
        incremental_conflict = 0.0
        for left_set, left_value in focal.items():
            for right_set, right_value in incoming.items():
                product = left_value * right_value
                intersection = left_set & right_set
                if intersection:
                    updated[intersection] = updated.get(intersection, 0.0) + product
                else:
                    incremental_conflict += product
        focal = updated
        conflicts.append({"source": mass.source, "incremental_conflict": incremental_conflict})

    total_conflict = max(0.0, 1.0 - sum(focal.values()))
    combined = _normalise(EvidenceMass(
        source="combined",
        phishing=focal.get(phishing, 0.0),
        benign=focal.get(benign, 0.0),
        uncertainty=focal.get(frame, 0.0) + total_conflict,
    ))

    # This is an experimental reporting policy, not the production verdict.
    if combined.phishing >= 0.75 and combined.uncertainty <= 0.45:
        verdict = "high_risk"
    elif combined.phishing >= 0.45:
        verdict = "review"
    elif combined.benign >= 0.75 and combined.uncertainty <= 0.25:
        verdict = "benign_supported"
    else:
        verdict = "insufficient_evidence"

    return {
        "fusion_version": FUSION_VERSION,
        "experimental": True,
        "affects_production_verdict": False,
        "phishing_support": combined.phishing,
        "benign_support": combined.benign,
        "uncertainty": combined.uncertainty,
        "verdict": verdict,
        "sources": [asdict(mass) for mass in discounted],
        "conflicts": conflicts,
        "total_conflict": total_conflict,
    }


def masses_from_result(result: dict) -> list[EvidenceMass]:
    """Translate existing DISE observations without re-running any engine."""
    decision = result.get("decision") or {}
    masses: list[EvidenceMass] = []
    profiles = {
        "attachment_malware": (0.99, 0.98),
        "official_domain_confusable": (0.95, 0.90),
        "unsafe_password_route": (0.92, 0.90),
        "authentication_failure": (0.85, 0.80),
        "semantic_ml_corroborated": (0.82, 0.60),
        "html_pair_ml_positive": (0.82, 0.70),
        "razor_catalogue_match": (0.75, 0.65),
        "attachment_structure_alert": (0.70, 0.65),
        "legacy_rule_threshold": (0.65, 0.55),
    }
    for signal in decision.get("signals") or []:
        if not signal.get("reflected") or signal.get("id") not in profiles:
            continue
        support, reliability = profiles[signal["id"]]
        masses.append(EvidenceMass(
            source=signal["id"],
            phishing=support,
            benign=0.0,
            uncertainty=1.0 - support,
            reliability=reliability,
            observation=signal.get("summary", ""),
        ))

    # Explicit engine failure is ignorance.  Keeping it as a source documents
    # coverage without moving support toward either class.
    for name in decision.get("unavailable_engines") or []:
        masses.append(EvidenceMass(source=f"unavailable:{name}", observation="engine unavailable"))
    attachment_failures = ((decision.get("attachment_scan") or {}).get("failures") or 0)
    if attachment_failures:
        masses.append(EvidenceMass(
            source="attachment_scan_incomplete",
            observation=f"{attachment_failures} attachment scan(s) incomplete",
        ))
    return masses


def experimental_fusion(result: dict) -> dict:
    return fuse_masses(masses_from_result(result))
