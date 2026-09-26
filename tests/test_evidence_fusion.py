from itertools import permutations
import unittest

from email_analyzer.evidence_fusion import EvidenceMass, experimental_fusion, fuse_masses
from email_analyzer.fusion_baselines import all_baselines


class EvidenceFusionTests(unittest.TestCase):
    def test_no_evidence_is_complete_uncertainty(self):
        result = fuse_masses([])
        self.assertEqual(result["phishing_support"], 0)
        self.assertEqual(result["benign_support"], 0)
        self.assertEqual(result["uncertainty"], 1)
        self.assertEqual(result["verdict"], "insufficient_evidence")

    def test_reliability_discount_moves_support_to_uncertainty(self):
        result = fuse_masses([EvidenceMass("source", phishing=0.8, uncertainty=0.2, reliability=0.5)])
        self.assertAlmostEqual(result["phishing_support"], 0.4)
        self.assertAlmostEqual(result["uncertainty"], 0.6)

    def test_conflict_is_not_normalised_into_false_confidence(self):
        result = fuse_masses([
            EvidenceMass("risk", phishing=1, uncertainty=0, reliability=0.9),
            EvidenceMass("safe", benign=1, uncertainty=0, reliability=0.9),
        ])
        self.assertAlmostEqual(result["total_conflict"], 0.81)
        self.assertAlmostEqual(result["uncertainty"], 0.82)
        self.assertEqual(result["verdict"], "insufficient_evidence")

    def test_fusion_is_independent_of_engine_order(self):
        masses = [
            EvidenceMass("a", phishing=0.8, uncertainty=0.2, reliability=0.7),
            EvidenceMass("b", benign=0.6, uncertainty=0.4, reliability=0.8),
            EvidenceMass("c", phishing=0.7, uncertainty=0.3, reliability=0.6),
        ]
        values = []
        for ordering in permutations(masses):
            result = fuse_masses(ordering)
            values.append((result["phishing_support"], result["benign_support"], result["uncertainty"]))
        for value in values[1:]:
            for observed, expected in zip(value, values[0]):
                self.assertAlmostEqual(observed, expected)

    def test_failed_attachment_scan_adds_only_uncertainty(self):
        result = experimental_fusion({
            "decision": {
                "signals": [],
                "attachment_scan": {"failures": 1},
                "unavailable_engines": ["semantic_ml"],
            }
        })
        self.assertEqual(result["phishing_support"], 0)
        self.assertEqual(result["benign_support"], 0)
        self.assertEqual(result["uncertainty"], 1)
        self.assertEqual({item["source"] for item in result["sources"]}, {
            "attachment_scan_incomplete", "unavailable:semantic_ml"
        })

    def test_baselines_use_the_same_normalised_sources(self):
        result = {"decision": {"verdict": "suspicious", "signals": [{
            "id": "official_domain_confusable", "reflected": True,
            "summary": "lookalike",
        }]}}
        values = all_baselines(result)
        self.assertEqual(values["production_policy"]["prediction"], 1)
        self.assertEqual(values["simple_mean"]["sources"], 1)
        self.assertEqual(values["reliability_weighted_mean"]["sources"], 1)
        self.assertEqual(values["majority_vote"]["prediction"], 1)


if __name__ == "__main__":
    unittest.main()
