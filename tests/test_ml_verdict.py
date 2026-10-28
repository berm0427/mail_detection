import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from email_analyzer.ml_verdict import analyze_ml_verdict
from email_analyzer.ml_verdict_features import FEATURE_NAMES, SCHEMA_VERSION, ml_verdict_feature_dict
from email_analyzer.reference_evidence import analyze_references
from tools.extract_synthetic_evidence import strip_label_headers
from tools.train_ml_verdict import validate_evidence_rows


def observed_result():
    return {
        "engine_results": {"semantic_ml": {"status": "ok", "score": 0.8, "details": {
            "model_id": "semantic-test", "regularization_c": 0.01,
            "manifest_sha256": "manifest-test",
        }}},
        "rule_result": {"auth_summary": {"failures": [{"method": "DKIM"}]}},
        "reference_evidence": {
            "from_reply_relation": "different_hosts",
            "from_return_path_relation": "same_hosts",
            "domain_relationships": [{"relationship": "external_domain", "roles": ["click_link"]},
                                     {"relationship": "same_sender_domain"}],
            "official_claim_mismatch_count": 1,
        },
        "link_evidence": {"different_host_count": 0},
        "page_analysis": {"status": "disabled", "pages": []},
        "attachments": [{"malware_scan": {"status": "threat_detected"}}],
    }


class MlVerdictTests(unittest.TestCase):
    def test_features_ignore_policy_outputs_rule_score_and_labels(self):
        base = observed_result()
        polluted = {**base, "verdict": "dangerous", "label": 1, "risk_score": 100,
                    "decision": {"signals": [{"id": "legacy_rule_threshold", "reflected": True}]},
                    "rule_result": {**base["rule_result"], "risk_score": 100, "verdict": "dangerous"}}
        self.assertEqual(ml_verdict_feature_dict(base), ml_verdict_feature_dict(polluted))

    def test_feature_values_come_from_observations(self):
        features = ml_verdict_feature_dict(observed_result())
        self.assertEqual(features["semantic_score"], 0.8)
        self.assertEqual(features["semantic_available"], 1.0)
        self.assertEqual(features["authentication_failure_count"], 1.0)
        self.assertEqual(features["from_reply_mismatch"], 1.0)
        self.assertEqual(features["from_return_path_mismatch"], 0.0)
        self.assertEqual(features["external_action_domain_present"], 1.0)
        self.assertEqual(features["attachment_threat_count"], 1.0)

    def test_failed_semantic_engine_is_unavailable_not_low_risk(self):
        result = observed_result()
        result["engine_results"]["semantic_ml"] = {"status": "error", "score": 0.0}
        features = ml_verdict_feature_dict(result)
        self.assertEqual((features["semantic_score"], features["semantic_available"]), (0.0, 0.0))

    def test_return_path_relation_is_observed(self):
        message = EmailMessage()
        message["From"] = "notice@sender.example"
        message["Return-Path"] = "<bounce@other.example>"
        message.set_content("body")
        evidence = analyze_references(message)
        self.assertEqual(evidence["return_path_hosts"], ["other.example"])
        self.assertEqual(evidence["from_return_path_relation"], "different_hosts")

    def _html_reference(self, html):
        message = EmailMessage()
        message["From"] = "notice@sender.example"
        message.set_content("plain body")
        message.add_alternative(html, subtype="html")
        return analyze_references(message)

    def _external_action_feature(self, html):
        result = observed_result()
        result["reference_evidence"] = self._html_reference(html)
        return ml_verdict_feature_dict(result)["external_action_domain_present"]

    def test_passive_external_resource_is_not_an_external_action(self):
        evidence = self._html_reference('<img src="https://cdn.other.example/pixel.png">')
        self.assertEqual(evidence["domain_relationships"][0]["roles"], ["passive_resource"])
        self.assertEqual(self._external_action_feature('<img src="https://cdn.other.example/pixel.png">'), 0.0)

    def test_external_anchor_is_an_external_action(self):
        self.assertEqual(self._external_action_feature('<a href="https://other.example/pay">open</a>'), 1.0)

    def test_external_form_action_is_an_external_action(self):
        self.assertEqual(self._external_action_feature('<form action="https://other.example/submit"></form>'), 1.0)

    def test_relative_targets_are_not_external_actions(self):
        self.assertEqual(self._external_action_feature('<a href="/help">help</a><img src="/logo.png">'), 0.0)

    def test_malformed_port_is_not_an_external_action(self):
        self.assertEqual(self._external_action_feature('<a href="https://other.example:bad/pay">open</a>'), 0.0)

    def test_same_registrable_domain_is_not_external_action(self):
        self.assertEqual(self._external_action_feature('<a href="https://account.sender.example/help">help</a>'), 0.0)

    def test_dataset_label_headers_are_stripped_before_analysis(self):
        raw = (b"Subject: s\r\nX-Dataset-Label: phishing\r\nX-Dataset-Split: train\r\n"
               b"X-Synthetic-Data: true\r\nFrom: a@b.example\r\n\r\nX-Dataset-Label: kept in body\r\n")
        cleaned, removed = strip_label_headers(raw)
        self.assertEqual(removed, 3)
        head, body = cleaned.split(b"\r\n\r\n", 1)
        self.assertNotIn(b"X-Dataset", head)
        self.assertIn(b"From: a@b.example", head)
        self.assertEqual(body, b"X-Dataset-Label: kept in body\r\n")

    def test_old_evidence_manifest_schema_is_rejected(self):
        row = {"feature_schema": "ml-verdict-features-v4", "label": 0,
               "group_id": "g", "analysis": {"verdict_status": "ok"}}
        with self.assertRaisesRegex(ValueError, "re-extract evidence"):
            validate_evidence_rows([row])

    def test_artifact_with_wrong_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            artifact = {"model_id": "m", "feature_schema": SCHEMA_VERSION,
                        "feature_names": list(FEATURE_NAMES), "coef": [0.0] * len(FEATURE_NAMES),
                        "intercept": 0.0, "promoted_to_gui": True,
                        "semantic_input": {"model_id": "semantic-test", "regularization_c": 0.01,
                                           "manifest_sha256": "manifest-test"}}
            path.write_text(json.dumps(artifact), encoding="utf-8")
            self.assertEqual(analyze_ml_verdict(observed_result(), path)["score"], 0.5)
            artifact["feature_names"] = list(reversed(FEATURE_NAMES))
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_ml_verdict(observed_result(), path)

    def test_unpromoted_artifact_is_rejected_by_production(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            artifact = {"model_id": "m", "feature_schema": SCHEMA_VERSION,
                        "feature_names": list(FEATURE_NAMES), "coef": [0.0] * len(FEATURE_NAMES),
                        "intercept": 0.0, "promoted_to_gui": False,
                        "semantic_input": {"model_id": "semantic-test", "regularization_c": 0.01,
                                           "manifest_sha256": "manifest-test"}}
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_ml_verdict(observed_result(), path, require_promoted=True)

    def test_semantic_provenance_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            artifact = {"model_id": "m", "feature_schema": SCHEMA_VERSION,
                        "feature_names": list(FEATURE_NAMES), "coef": [0.0] * len(FEATURE_NAMES),
                        "intercept": 0.0, "promoted_to_gui": True,
                        "semantic_input": {"model_id": "other-model", "regularization_c": 0.01,
                                           "manifest_sha256": "manifest-test"}}
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_ml_verdict(observed_result(), path, require_promoted=True)


if __name__ == "__main__":
    unittest.main()
