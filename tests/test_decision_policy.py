import unittest

from email_analyzer.decision import combine_evidence


def result(semantic=0.0, threat=False, razor=False, **extra):
    data = {
        "verdict": "suspicious",
        "engine_results": {
            "semantic_ml": {"status": "ok", "score": semantic},
            "razor": {"status": "ok", "details": {"catalogue_match": razor}},
        },
        "attachments": [{"malware_scan": {"status": "threat_detected" if threat else "clean"}}],
        "rule_result": {"risk_score": 0, "auth_summary": {}},
        "reference_evidence": {}, "link_evidence": {}, "page_analysis": {"status": "disabled", "pages": []},
    }
    data.update(extra)
    return data


class DecisionPolicyTests(unittest.TestCase):
    def test_ml_negative_without_external_detection_has_no_signal(self):
        self.assertEqual(combine_evidence(result(semantic=0.0))["verdict"], "no_signal")

    def test_ml_positive_alone_is_suspicious(self):
        self.assertEqual(combine_evidence(result(semantic=0.99))["verdict"], "suspicious")

    def test_external_detection_with_ml_negative_is_suspicious(self):
        self.assertEqual(combine_evidence(result(semantic=0.0, threat=True))["verdict"], "suspicious")
        self.assertEqual(combine_evidence(result(semantic=0.0, razor=True))["verdict"], "suspicious")

    def test_external_detection_with_ml_positive_is_dangerous(self):
        self.assertEqual(combine_evidence(result(semantic=0.99, threat=True))["verdict"], "dangerous")
        self.assertEqual(combine_evidence(result(semantic=0.99, razor=True))["verdict"], "dangerous")

    def test_missing_semantic_score_is_inconclusive_not_safe(self):
        data = result()
        data["engine_results"]["semantic_ml"] = {"status": "error", "score": None}
        decision = combine_evidence(data)
        self.assertEqual(decision["verdict"], "inconclusive")
        self.assertIn("ml_verdict", decision["unavailable_engines"])

    def test_failed_attachment_scan_is_not_malware(self):
        data = result()
        data["attachments"] = [{"malware_scan": {"status": "error"}}]
        decision = combine_evidence(data)
        self.assertEqual(decision["verdict"], "no_signal")
        self.assertEqual(decision["attachment_scan"]["failures"], 1)

    def test_other_observations_are_reference_only(self):
        data = result(
            semantic=0.0,
            rule_result={"risk_score": 100, "auth_summary": {"failures": [{"method": "SPF"}]}},
            homepage_comparison={"official_external_action_routes": [
                {"organization": "기관", "target_host": "unrelated.example"}]},
        )
        decision = combine_evidence(data)
        self.assertEqual(decision["verdict"], "no_signal")
        reflected = {item["id"] for item in decision["signals"] if item["reflected"]}
        self.assertEqual(reflected, set())
        observed = {item["id"] for item in decision["signals"]}
        self.assertTrue({"authentication_failure", "official_claim_external_route"} <= observed)

    def test_parse_error_stays_error(self):
        self.assertEqual(combine_evidence(result(semantic=0.99, verdict="error"))["verdict"], "error")


if __name__ == "__main__":
    unittest.main()
