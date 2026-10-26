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

    def test_external_observations_do_not_override_ml_negative(self):
        for decision in (combine_evidence(result(semantic=0.0, threat=True)),
                         combine_evidence(result(semantic=0.0, razor=True))):
            self.assertEqual(decision["verdict"], "no_signal")
            self.assertFalse(any(item["reflected"] for item in decision["signals"]))

    def test_external_observations_do_not_escalate_ml_positive(self):
        for decision in (combine_evidence(result(semantic=0.99, threat=True)),
                         combine_evidence(result(semantic=0.99, razor=True))):
            self.assertEqual(decision["verdict"], "suspicious")
            reflected = [item for item in decision["signals"] if item["reflected"]]
            self.assertEqual([item["id"] for item in reflected], ["ml_verdict"])

    def test_antivirus_report_is_observation_not_ground_truth(self):
        decision = combine_evidence(result(semantic=0.0, threat=True))
        observation = next(item for item in decision["signals"]
                           if item["id"] == "attachment_antivirus_report")
        self.assertFalse(observation["reflected"])
        self.assertEqual(observation["severity"], "advisory")
        self.assertIn("백신 엔진 위협 보고", observation["summary"])

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

    def test_clean_ml_negative_does_not_require_review(self):
        decision = combine_evidence(result(semantic=0.0))
        self.assertFalse(decision["review_required"])
        self.assertEqual(decision["overall_status"], "no_signal")
        self.assertEqual(decision["review_observations"], [])

    def test_observation_with_ml_negative_requires_review_without_changing_verdict(self):
        for data in (result(semantic=0.0, threat=True), result(semantic=0.0, razor=True),
                     result(semantic=0.0, rule_result={"auth_summary": {"failures": [{"method": "DKIM"}]}})):
            decision = combine_evidence(data)
            self.assertEqual(decision["verdict"], "no_signal")
            self.assertEqual(decision["overall_status"], "review_required")
            self.assertTrue(decision["review_required"])
            self.assertNotIn("ml_verdict", decision["review_observations"])

    def test_ml_positive_and_unavailable_require_review(self):
        self.assertTrue(combine_evidence(result(semantic=0.99))["review_required"])
        data = result()
        data["engine_results"]["semantic_ml"] = {"status": "error"}
        self.assertTrue(combine_evidence(data)["review_required"])

    def test_parse_error_stays_error(self):
        self.assertEqual(combine_evidence(result(semantic=0.99, verdict="error"))["verdict"], "error")


if __name__ == "__main__":
    unittest.main()
