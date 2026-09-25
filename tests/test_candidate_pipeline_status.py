"""Exercise status reporting with real offline evaluation, not real training."""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from email_analyzer.evidence_features import EvidenceFeatureExtractor
from tools import run_evidence_candidate_pipeline as pipeline


class CandidatePipelineStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.training = self.root / "training.jsonl"
        self.external = self.root / "external.jsonl"
        rows = []
        for index in range(3):
            message = EmailMessage()
            message.set_content(f"independent fixture body {index}")
            eml = self.root / f"{index}.eml"
            eml.write_bytes(message.as_bytes())
            rows.append({"eml": eml.name, "label": index % 2,
                         "group_id": f"fixture-{index}", "split": "train"})
        self.training.write_text(json.dumps(rows[0]), encoding="utf-8")
        self.external.write_text("\n".join(json.dumps(r) for r in rows[1:]), encoding="utf-8")
        self.candidate = self.root / "candidate.json"
        self.approved = self.root / "approved.json"
        self.approved.write_bytes(b"existing approved artifact")
        self.report = self.candidate.with_suffix(".external.json")
        self.status = self.candidate.with_suffix(".pipeline.json")
        features = list(EvidenceFeatureExtractor.FEATURE_NAMES)
        size = len(features)
        self.model = {
            "model_id": "status-fixture", "schema_version": 1,
            "feature_names": features, "positive_class": "label_1",
            "text_bins": 0, "text_coef": [], "intercept": 0.0,
            "mean": [0.0] * size, "scale": [1.0] * size,
            "evidence_coef": [0.0] * size,
        }

    def run_pipeline(self, *, invalid_model=False, relaxed=False):
        # Stub only training (unavailable optional packages). Run the actual
        # independence check and evaluator CLI against temporary local files.
        def run(command):
            if "email_analyzer.train_evidence_ml" in command:
                self.candidate.write_text(json.dumps({} if invalid_model else self.model),
                                          encoding="utf-8")
                return subprocess.CompletedProcess(command, 0)
            self.assertIn("email_analyzer.evaluate_evidence_ml", command)
            completed = subprocess.run([command[0], "-B", "-S", *command[1:]],
                                       capture_output=True, text=True, timeout=15)
            self.evaluation_returncode = completed.returncode
            return completed

        argv = ["pipeline", str(self.training), str(self.external), str(self.candidate),
                str(self.approved), "--model-id", "status-fixture"]
        if relaxed:
            argv += ["--external-min-rows", "2", "--external-min-auc", "0",
                     "--external-max-fpr", "1", "--external-min-recall", "0"]
        self.evaluation_returncode = None
        exit_code = 0
        with patch.object(sys, "argv", argv), patch.object(pipeline, "run", side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                pipeline.main()
            except SystemExit as exc:
                exit_code = exc.code
        return exit_code, json.loads(self.status.read_text(encoding="utf-8"))

    def assert_failure_status(self, exit_code, status, evaluation_code):
        self.assertEqual(exit_code, 2)
        self.assertEqual(self.evaluation_returncode, evaluation_code)
        self.assertEqual(status["external_returncode"], evaluation_code)
        self.assertTrue(status["trained"])
        self.assertTrue(status["input_independence"]["passed"])
        self.assertFalse(status["external_gate_passed"])
        self.assertFalse(status["approved"])
        self.assertFalse(status["production_config_changed"])
        self.assertEqual(self.approved.read_bytes(), b"existing approved artifact")

    def test_inference_failure_does_not_reuse_previous_passing_gate(self):
        old_report = b'{"promotion_allowed": true, "model_id": "old-model"}\n'
        self.report.write_bytes(old_report)
        code, status = self.run_pipeline(invalid_model=True)
        self.assertEqual(self.report.read_bytes(), old_report)
        self.assert_failure_status(code, status, 1)

    def test_inference_failure_ignores_malformed_previous_report(self):
        old_report = b"previous interrupted report"
        self.report.write_bytes(old_report)
        code, status = self.run_pipeline(invalid_model=True)
        self.assertEqual(self.report.read_bytes(), old_report)
        self.assert_failure_status(code, status, 1)

    def test_inference_failure_without_previous_report(self):
        code, status = self.run_pipeline(invalid_model=True)
        self.assertFalse(self.report.exists())
        self.assert_failure_status(code, status, 1)

    def test_current_gate_failure_replaces_old_report_but_not_approved_model(self):
        self.report.write_text('{"promotion_allowed": true}', encoding="utf-8")
        code, status = self.run_pipeline()
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(report["model_id"], "status-fixture")
        self.assertFalse(report["promotion_allowed"])
        self.assert_failure_status(code, status, 2)

    def test_current_success_still_approves_temporary_fixture(self):
        self.report.write_bytes(b"previous interrupted report")
        code, status = self.run_pipeline(relaxed=True)
        self.assertEqual(code, 0)
        self.assertEqual(self.evaluation_returncode, 0)
        self.assertTrue(status["external_gate_passed"])
        self.assertTrue(status["approved"])
        self.assertEqual(self.approved.read_bytes(), self.candidate.read_bytes())
        self.assertTrue(json.loads(self.report.read_text())["promotion_allowed"])


if __name__ == "__main__":
    unittest.main()
