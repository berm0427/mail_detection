from itertools import permutations
import unittest

from email_analyzer.evidence_fusion import EvidenceMass, experimental_fusion, fuse_masses
from email_analyzer.fusion_baselines import all_baselines
from email_analyzer.fusion_features import FEATURE_NAMES, fusion_feature_dict, fusion_feature_vector
from email_analyzer.learned_fusion import analyze_learned_fusion


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

    def test_meta_features_do_not_read_final_verdict_or_label(self):
        base = {"decision": {"signals": [], "attachment_scan": {}, "html_review": {}},
                "engine_results": {}, "rule_result": {"risk_score": 0}}
        changed = dict(base, verdict="dangerous", label=1)
        self.assertEqual(fusion_feature_vector(base), fusion_feature_vector(changed))
        self.assertEqual(len(fusion_feature_vector(base)), len(FEATURE_NAMES))

    def test_meta_features_preserve_engine_availability(self):
        result = {"decision": {"signals": [], "attachment_scan": {}, "html_review": {}},
                  "engine_results": {"semantic_ml": {"score": 0.8},
                                     "html_pair_ml": {"status": "error"}},
                  "rule_result": {"risk_score": 25}}
        features = fusion_feature_dict(result)
        self.assertEqual(features["semantic_available"], 1)
        self.assertEqual(features["html_pair_available"], 0)
        self.assertEqual(features["rule_score"], 0.25)

    def test_learned_fusion_rejects_wrong_schema(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            path.write_text(json.dumps({"model_id": "bad", "feature_names": [],
                                        "coef": [], "intercept": 0}), encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_learned_fusion({}, path)


if __name__ == "__main__":
    unittest.main()
