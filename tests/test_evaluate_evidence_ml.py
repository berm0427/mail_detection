import json
import random
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from email_analyzer.evaluate_evidence_ml import binary_metrics
from email_analyzer.evidence_features import EvidenceFeatureExtractor
from email_analyzer.manifest_independence import normalized_body_sha256


class BinaryMetricsTests(unittest.TestCase):
    def test_labels_require_exact_binary_integers(self):
        for value in (False, True, 0.0, 1.0, "0", "1", None, -1, 2, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    binary_metrics([0, 1, value], [.1, .9, .5])

    def test_perfect_and_reversed_rankings(self):
        for scores, auc in (([.1, .9], 1.0), ([.9, .1], 0.0)):
            with self.subTest(scores=scores):
                result = binary_metrics([0, 1], scores)
                self.assertEqual(result["auc"], auc)
                self.assertEqual(result["accuracy"], auc)

    def test_constant_scores_and_threshold_boundary(self):
        result = binary_metrics([0, 1, 0, 1], [.5] * 4)
        self.assertEqual(result, {"rows": 4, "auc": .5, "tn": 0, "fp": 2,
                                  "fn": 0, "tp": 2, "accuracy": .5,
                                  "fpr": 1.0, "recall": 1.0})

    def test_mixed_ties_and_confusion_counts(self):
        result = binary_metrics([0, 0, 1, 1], [.1, .5, .5, .9])
        self.assertEqual(result, {"rows": 4, "auc": .875, "tn": 1, "fp": 1,
                                  "fn": 0, "tp": 2, "accuracy": .75,
                                  "fpr": .5, "recall": 1.0})

    def test_auc_matches_pairwise_oracle_for_ties_and_imbalanced_labels(self):
        rng = random.Random(20260924)
        for _ in range(100):
            labels = [0, 1] + [rng.randrange(2) for _ in range(rng.randrange(30))]
            scores = [rng.choice([0, .1, .5, .9, 1]) for _ in labels]
            positive = [s for y, s in zip(labels, scores) if y == 1]
            negative = [s for y, s in zip(labels, scores) if y == 0]
            expected = sum((p > n) + .5 * (p == n) for p in positive for n in negative)
            expected /= len(positive) * len(negative)
            self.assertAlmostEqual(binary_metrics(labels, scores)["auc"], expected)
            self.assertEqual(binary_metrics(labels, scores),
                             binary_metrics(labels[::-1], scores[::-1]))

    def test_invalid_inputs_fail_closed(self):
        cases = [([], []), ([0, 0], [.1, .2]), ([1, 1], [.8, .9]),
                 ([0, 1], [.1]), ([0, 2], [.1, .9])]
        cases.extend(([0, 1], [.1, value]) for value in
                     (float("nan"), float("inf"), float("-inf"), -.1, 1.1))
        for labels, scores in cases:
            with self.subTest(labels=labels, scores=scores):
                with self.assertRaises(ValueError):
                    binary_metrics(labels, scores)


class IndependentEvaluationTests(unittest.TestCase):
    def test_bad_model_is_not_promotable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            model = {
                "model_id": "constant-test", "schema_version": 1,
                "feature_names": [
                    "url_total","url_risky","url_rule_score","url_http","display_target_mismatch",
                    "official_claim_mismatch","from_reply_mismatch","unregistered_link_hosts",
                    "page_targets","page_fetch_ok","page_fetch_failed","page_forms","page_password_fields",
                    "page_external_forms","page_http_forms","page_iframes","page_scripts","auth_failures",
                    "auth_missing","auth_errors","keyword_matches","urgent_action_requests","attachment_count",
                    "attachment_megabytes","executable_attachments","attachment_threats","attachment_alerts",
                    "attachment_scan_failures"],
                "text_bins": 8, "positive_class": "label_1", "decision_threshold": .5,
                "mean": [0.0] * 28, "scale": [1.0] * 28, "evidence_coef": [0.0] * 28,
                "text_coef": [0.0] * 8, "intercept": 0.0,
            }
            model_path = root / "model.json"
            model_path.write_text(json.dumps(model), encoding="utf-8")
            rows = []
            for index, label in enumerate((0, 1, 0, 1)):
                message = EmailMessage(); message["Subject"] = f"unique {index}"; message.set_content(f"body {index}")
                eml = root / f"{index}.eml"; eml.write_bytes(message.as_bytes())
                rows.append({"eml": eml.name, "label": label, "analysis": {"url_analysis": {}}})
            manifest = root / "manifest.jsonl"
            manifest.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            report = root / "report.json"
            completed = subprocess.run([
                sys.executable, "-S", "-m", "email_analyzer.evaluate_evidence_ml", str(model_path),
                str(manifest), str(report), "--min-rows", "4"], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(result["promotion_allowed"])


class StandaloneUniquenessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = self.root / "model.json"
        features = list(EvidenceFeatureExtractor.FEATURE_NAMES)
        size = len(features)
        self.model.write_text(json.dumps({
            "model_id": "uniqueness-fixture", "schema_version": 1,
            "feature_names": features, "positive_class": "label_1",
            "text_bins": 0, "text_coef": [], "intercept": 0.0,
            "mean": [0.0] * size, "scale": [1.0] * size,
            "evidence_coef": [0.0] * size,
        }), encoding="utf-8")
        self.manifest = self.root / "manifest.jsonl"
        self.report = self.root / "report.json"
        self.rows = []

    def add(self, body, *, subtype="plain", cte="quoted-printable"):
        index = len(self.rows)
        message = EmailMessage()
        message["Subject"] = f"private-subject-{index}"
        message["From"] = f"private-sender-{index}@example.org"
        message.set_content(body, subtype=subtype, cte=cte)
        path = self.root / f"private-message-{index}.eml"
        path.write_bytes(message.as_bytes())
        self.rows.append({"eml": path.name, "label": index % 2,
                          "group_id": "shared-campaign"})
        # Keep a blank line so errors must count physical, not logical rows.
        self.manifest.write_text("\n\n".join(json.dumps(r) for r in self.rows) + "\n",
                                 encoding="utf-8")
        return path

    def run_evaluation(self, *extra_args):
        return subprocess.run([
            sys.executable, "-B", "-S", "-m", "email_analyzer.evaluate_evidence_ml",
            str(self.model), str(self.manifest), str(self.report),
            "--min-rows", "2", "--min-auc", "0", "--max-fpr", "1", "--min-recall", "0",
            *extra_args,
        ], capture_output=True, text=True, timeout=15)

    def assert_rejected(self, completed, reason):
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(reason + " at line 3", completed.stderr)
        for private in ("private-subject", "private-sender", "private-message", "sensitive body"):
            self.assertNotIn(private, completed.stdout + completed.stderr)

    def test_invalid_gate_criteria_preserve_inputs_and_reports(self):
        self.add("first independent body")
        self.add("second independent body")
        cases = [(flag, value) for flag in ("--min-auc", "--max-fpr", "--min-recall")
                 for value in ("nan", "inf", "-inf", "1e999", "-0.01", "1.01")]
        cases.extend(("--min-rows", value) for value in ("0", "-1"))
        for existing in (False, True):
            for flag, value in cases:
                with self.subTest(existing=existing, flag=flag, value=value):
                    # Each invalid invocation must leave a fresh destination absent.
                    self.report = self.root / f"report-{existing}-{flag}-{value}.json"
                    if existing:
                        self.report.write_bytes(b"previous report must survive")
                    before = {p: p.read_bytes() for p in self.root.iterdir()}
                    completed = self.run_evaluation(f"{flag}={value}")
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertIn("error: argument " + flag, completed.stderr)
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_invalid_gate_criteria_are_rejected_before_input_reads(self):
        for flag, value in (("--min-rows", "0"), ("--min-auc", "nan"),
                            ("--max-fpr", "inf"), ("--min-recall", "-1")):
            with self.subTest(flag=flag):
                # No manifest exists; an argument diagnostic must take precedence.
                self.report = self.root / "uncreated" / "report.json"
                completed = self.run_evaluation(f"{flag}={value}")
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn("error: argument " + flag, completed.stderr)
                self.assertNotIn("Traceback", completed.stderr)
                self.assertFalse(self.report.parent.exists())

    def test_gate_criteria_allow_probability_boundaries_and_positive_rows(self):
        self.add("first independent body")
        self.add("second independent body")
        for args, expected_code in (
            (("--min-rows=1", "--min-auc=0", "--max-fpr=1", "--min-recall=0"), 0),
            (("--min-rows=3", "--min-auc=1", "--max-fpr=0", "--min-recall=1"), 2),
        ):
            with self.subTest(args=args):
                completed = self.run_evaluation(*args)
                self.assertEqual(completed.returncode, expected_code, completed.stderr)
                report = json.loads(self.report.read_text())
                expected = {flag[2:].split("=")[0].replace("-", "_"): float(flag.split("=")[1])
                            for flag in args}
                self.assertEqual(report["criteria"], expected)
                self.assertEqual(report["promotion_allowed"], expected_code == 0)

    def test_normalized_duplicates_cannot_pass_even_relaxed_gate(self):
        self.add("sensitive body")
        self.add("  SENSITIVE\n\tBODY  ", cte="base64")
        self.assert_rejected(self.run_evaluation(), "normalized body duplicate within external manifest")
        self.assertFalse(self.report.exists())

    def test_html_plain_duplicates_are_rejected(self):
        self.add("sensitive body")
        self.add("<html><head><title>ignored</title></head><body><p>Sensitive BODY</p></body></html>",
                 subtype="html")
        self.assert_rejected(self.run_evaluation(), "normalized body duplicate within external manifest")
        self.assertFalse(self.report.exists())

    def test_raw_duplicates_remain_rejected(self):
        first = self.add("sensitive body")
        second = self.add("different")
        second.write_bytes(first.read_bytes())
        self.assert_rejected(self.run_evaluation(), "duplicate EML content")
        self.assertFalse(self.report.exists())

    def test_rejection_preserves_existing_report_and_inputs(self):
        self.add("sensitive body")
        self.add("SENSITIVE BODY", cte="base64")
        self.report.write_bytes(b"existing report must not change")
        before = {p: p.read_bytes() for p in self.root.iterdir()}
        self.assert_rejected(self.run_evaluation(), "normalized body duplicate within external manifest")
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_distinct_bodies_in_same_group_are_allowed(self):
        self.add("first independent body")
        self.add("second independent body")
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)

    def test_distinct_empty_messages_are_not_body_duplicates(self):
        self.add("")
        self.add("")
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_long_bodies_with_distinct_suffixes_are_not_truncated(self):
        prefix = "shared prefix " * 10000
        self.add(prefix + "first")
        self.add(prefix + "second")
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_body_fingerprint_preserves_subject_headers_and_mime_payload(self):
        message = EmailMessage()
        message["Subject"] = "Keep this inference feature"
        message["From"] = "fixture@example.org"
        message.set_content("sensitive body")
        message.add_alternative("<p>sensitive body</p>", subtype="html")
        before = message.as_bytes()
        fingerprint = normalized_body_sha256(message)
        self.assertIsNotNone(fingerprint)
        self.assertEqual(message.as_bytes(), before)
        message.replace_header("Subject", "Different subject")
        self.assertEqual(normalized_body_sha256(message), fingerprint)

    def assert_output_collision_preserves_inputs(self, target, alias=None):
        if alias == "symlink":
            self.report.symlink_to(target)
        elif alias == "hardlink":
            self.report.hardlink_to(target)
        else:
            self.report = target
        before = {p: p.read_bytes() for p in self.root.iterdir()}
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("report path aliases an evaluation input", completed.stderr)
        self.assertNotIn("private-message", completed.stdout + completed.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def prepare_collision_inputs(self):
        first = self.add("first independent body")
        self.add("second independent body")
        analysis = self.root / "private-analysis.json"
        analysis.write_text("{}", encoding="utf-8")
        self.rows[0]["analysis_result"] = analysis.name
        self.manifest.write_text("\n".join(json.dumps(r) for r in self.rows), encoding="utf-8")
        return first, analysis

    def test_report_cannot_overwrite_model(self):
        self.prepare_collision_inputs()
        self.assert_output_collision_preserves_inputs(self.model)

    def test_report_cannot_overwrite_manifest(self):
        self.prepare_collision_inputs()
        self.assert_output_collision_preserves_inputs(self.manifest)

    def test_report_cannot_overwrite_eml(self):
        eml, _ = self.prepare_collision_inputs()
        self.assert_output_collision_preserves_inputs(eml)

    def test_report_cannot_overwrite_analysis_result(self):
        _, analysis = self.prepare_collision_inputs()
        self.assert_output_collision_preserves_inputs(analysis)

    def test_report_symlink_to_input_is_rejected(self):
        self.prepare_collision_inputs()
        self.assert_output_collision_preserves_inputs(self.model, "symlink")

    def test_report_hardlink_to_input_is_rejected(self):
        eml, _ = self.prepare_collision_inputs()
        self.assert_output_collision_preserves_inputs(eml, "hardlink")

    def test_report_parent_symlink_to_input_directory_is_rejected(self):
        self.prepare_collision_inputs()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.report = alias / self.model.name
        before = self.model.read_bytes()
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("report path aliases an evaluation input", completed.stderr)
        self.assertEqual(self.model.read_bytes(), before)

    def test_existing_non_input_report_can_still_be_updated(self):
        self.prepare_collision_inputs()
        self.report.write_text("old report", encoding="utf-8")
        before = {p: p.read_bytes() for p in self.root.iterdir() if p != self.report}
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir() if p != self.report})

    def check_invalid_labels(self, values, *, existing_report):
        self.add("first independent body")
        self.add("second independent body")
        for value in values:
            with self.subTest(value=value):
                # Keep both classes even if the invalid label is coerced to 0;
                # rejection must come from the schema, not single-class metrics.
                rows = [dict(self.rows[0], label=1 - int(bool(value))),
                        dict(self.rows[1], label=value)]
                self.manifest.write_text("\n\n".join(json.dumps(r) for r in rows), encoding="utf-8")
                if existing_report:
                    self.report.write_bytes(b"previous report must survive")
                before = {p: p.read_bytes() for p in self.root.iterdir()}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assert_rejected(completed, "invalid label")
                self.assertEqual(completed.stdout, "")
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_boolean_labels_are_not_coerced_or_reported(self):
        self.check_invalid_labels((False, True), existing_report=False)

    def test_float_labels_are_not_coerced_or_reported(self):
        self.check_invalid_labels((0.0, 1.0), existing_report=False)

    def test_invalid_label_rejection_preserves_previous_report(self):
        self.check_invalid_labels((False, True, 0.0, 1.0), existing_report=True)

    def test_other_invalid_labels_remain_rejected(self):
        self.check_invalid_labels(("0", "1", None, -1, 2, [], {}), existing_report=True)

    def save_rows(self):
        self.manifest.write_text("\n\n".join(json.dumps(r) for r in self.rows), encoding="utf-8")

    def check_invalid_analysis(self, *, fallback):
        self.add("first independent body")
        self.add("second independent body")
        if fallback:
            analysis = self.root / "private-analysis.json"
            analysis.write_text("{}", encoding="utf-8")
            self.rows[1]["analysis_result"] = analysis.name
        for value in (None, False, 0, "private-analysis-value", [], [1]):
            with self.subTest(value=value):
                self.rows[1]["analysis"] = value
                self.save_rows()
                self.report.write_bytes(b"previous report must survive")
                before = {p: p.read_bytes() for p in self.root.iterdir()}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assert_rejected(completed, "invalid analysis")
                self.assertNotIn("private-analysis", completed.stdout + completed.stderr)
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_invalid_inline_analysis_is_not_silently_empty(self):
        self.check_invalid_analysis(fallback=False)

    def test_invalid_inline_analysis_is_not_hidden_by_file_fallback(self):
        self.check_invalid_analysis(fallback=True)

    def test_invalid_analysis_file_is_rejected_with_safe_line_number(self):
        self.add("first independent body")
        self.add("second independent body")
        analysis = self.root / "private-analysis.json"
        self.rows[1]["analysis_result"] = analysis.name
        self.save_rows()
        for content in (b"[]", b"null", b"false", b"0", b'"private-analysis-value"',
                        b"private malformed JSON", b"\xff"):
            with self.subTest(content=content):
                analysis.write_bytes(content)
                before = {p: p.read_bytes() for p in self.root.iterdir()}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assert_rejected(completed, "invalid or unavailable analysis_result")
                self.assertNotIn("private-analysis", completed.stdout + completed.stderr)
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_inline_analysis_including_empty_object_takes_precedence_like_training(self):
        self.add("first independent body")
        self.add("second independent body")
        model = json.loads(self.model.read_text())
        model["intercept"] = -1.0
        model["evidence_coef"][0] = 2.0
        self.model.write_text(json.dumps(model))
        analysis = self.root / "private-analysis.json"
        analysis.write_text(json.dumps({"url_analysis": {"total_urls": 1}}))
        for inline in ({}, {"url_analysis": {"total_urls": 0}}):
            with self.subTest(inline=inline):
                for row in self.rows:
                    row.update(analysis=inline, analysis_result=analysis.name)
                self.save_rows()
                before = {p: p.read_bytes() for p in self.root.iterdir() if p != self.report}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 0, completed.stderr)
                report = json.loads(self.report.read_text())
                self.assertEqual([p["prediction"] for p in report["predictions"]], [0, 0])
                self.assertAlmostEqual(report["predictions"][0]["score"], 0.2689414213699951)
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir() if p != self.report})

    def test_analysis_file_used_when_inline_is_absent(self):
        self.add("first independent body")
        self.add("second independent body")
        model = json.loads(self.model.read_text())
        model["intercept"] = -1.0
        model["evidence_coef"][0] = 2.0
        self.model.write_text(json.dumps(model))
        analysis = self.root / "private-analysis.json"
        analysis.write_text(json.dumps({"url_analysis": {"total_urls": 1}}))
        self.rows[1]["analysis_result"] = analysis.name
        self.save_rows()
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual([p["prediction"] for p in report["predictions"]], [0, 1])

    def check_eml_rejection(self, value, reason, *, existing_report):
        self.rows[1]["eml"] = value
        self.save_rows()
        if existing_report:
            self.report.write_bytes(b"previous report must survive")
        before = {p: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assert_rejected(completed, reason)
        self.assertEqual(completed.stdout, "")
        self.assertNotIn("private-eml", completed.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir() if p.is_file()})

    def check_invalid_analysis_references(self, *, existing_report):
        self.add("first independent body")
        self.add("second independent body")
        values = (None, False, True, 0, 123, 1.5, [], [1], {}, {"private-analysis": 1}, "", " \t")
        # Real files at coerced names prove rejection is not just missing I/O.
        for value in values:
            if not isinstance(value, str):
                (self.root / str(value)).write_text("{}", encoding="utf-8")
        for value in values:
            with self.subTest(value=value):
                self.rows[1]["analysis_result"] = value
                self.save_rows()
                if existing_report:
                    self.report.write_bytes(b"previous report must survive")
                before = {p: p.read_bytes() for p in self.root.iterdir()}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assert_rejected(completed, "invalid analysis_result")
                self.assertEqual(completed.stdout, "")
                self.assertNotIn("private-analysis", completed.stderr)
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_analysis_reference_requires_nonblank_string_without_report(self):
        self.check_invalid_analysis_references(existing_report=False)

    def test_invalid_analysis_reference_preserves_existing_report_and_inputs(self):
        self.check_invalid_analysis_references(existing_report=True)

    def test_inline_analysis_does_not_consume_invalid_file_reference(self):
        self.add("first independent body")
        self.add("second independent body")
        for value in (None, False, 123, [], {}, "", " \t", "private-analysis-missing"):
            with self.subTest(value=value):
                self.rows[1].update(analysis={}, analysis_result=value)
                self.save_rows()
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)

    def test_analysis_reference_relative_and_absolute_paths_use_file_evidence(self):
        self.add("first independent body")
        self.add("second independent body")
        model = json.loads(self.model.read_text())
        model["intercept"] = -1.0
        model["evidence_coef"][0] = 2.0
        self.model.write_text(json.dumps(model))
        analysis = self.root / "분석 근거.json"
        analysis.write_text(json.dumps({"url_analysis": {"total_urls": 1}}))
        for value in (analysis.name, str(analysis)):
            with self.subTest(value=value):
                self.rows[1]["analysis_result"] = value
                self.save_rows()
                before = {p: p.read_bytes() for p in self.root.iterdir() if p != self.report}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 0, completed.stderr)
                predictions = json.loads(self.report.read_text())["predictions"]
                self.assertEqual([p["prediction"] for p in predictions], [0, 1])
                self.assertAlmostEqual(predictions[1]["score"], 0.7310585786300049)
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir() if p != self.report})

    def test_eml_field_requires_nonempty_string(self):
        self.add("first independent body")
        second = self.add("second independent body")
        # These names exist: coercion must not accidentally evaluate them.
        for value in (123, False, None, [], {}):
            (self.root / str(value)).write_bytes(second.read_bytes())
        for value in (123, False, None, [], {}, "", " \t"):
            with self.subTest(value=value):
                self.check_eml_rejection(value, "invalid eml", existing_report=False)

    def test_missing_eml_field_has_safe_physical_line_number(self):
        self.add("first independent body")
        self.add("second independent body")
        del self.rows[1]["eml"]
        self.save_rows()
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assert_rejected(completed, "invalid eml")
        self.assertFalse(self.report.exists())

    def test_unavailable_eml_preserves_report_without_disclosing_path(self):
        self.add("first independent body")
        self.add("second independent body")
        directory = self.root / "private-eml-directory"
        directory.mkdir()
        loop = self.root / "private-eml-loop"
        loop.symlink_to(loop.name)
        for value in ("private-eml-missing", directory.name, loop.name, "private-eml\0invalid"):
            with self.subTest(value=value):
                self.check_eml_rejection(value, "invalid or unavailable eml", existing_report=True)

    def test_absolute_eml_paths_remain_supported(self):
        self.add("first independent body")
        self.add("second independent body")
        for row in self.rows:
            row["eml"] = str(self.root / row["eml"])
        self.save_rows()
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)

    def check_invalid_manifest_rows(self, values, reason, *, existing_report):
        self.add("first independent body")
        self.add("second independent body")
        for value in values:
            with self.subTest(value=value):
                self.manifest.write_bytes(json.dumps(self.rows[0]).encode() + b"\r\n \t\r\n" + value)
                if existing_report:
                    self.report.write_bytes(b"previous report must survive")
                before = {p: p.read_bytes() for p in self.root.iterdir()}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assert_rejected(completed, reason)
                self.assertNotIn("private-jsonl", completed.stdout + completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_non_object_manifest_rows_have_physical_line_diagnostics(self):
        self.check_invalid_manifest_rows(
            (b'null', b'true', b'0', b'0.5', b'[]', b'[{}]', b'"private-jsonl"'),
            "manifest row must be a JSON object", existing_report=False)

    def test_malformed_jsonl_preserves_report_with_physical_line_diagnostics(self):
        self.check_invalid_manifest_rows(
            (b'{"private-jsonl":', b'{"private-jsonl": 1,}', b'{} {}'),
            "invalid manifest JSON", existing_report=True)

    def test_invalid_utf8_jsonl_preserves_report_with_physical_line_diagnostics(self):
        self.check_invalid_manifest_rows(
            (b'{"private-jsonl": "\xff"}',),
            "invalid manifest JSON", existing_report=True)

    def test_crlf_blank_lines_and_unicode_json_strings_remain_valid(self):
        self.add("first independent body")
        self.add("second independent body")
        self.rows[0]["source"] = "검토한 자료\u2028다음 구분"
        self.manifest.write_bytes(b"\r\n \t\r\n" + b"\r\n\r\n".join(
            json.dumps(row, ensure_ascii=False).encode("utf-8") for row in self.rows) + b"\r\n")
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)

    def check_duplicate_manifest_keys(self, *, existing_report):
        self.add("first independent body")
        self.add("second independent body")
        # Each first value would previously be silently replaced by the last.
        cases = (
            '"label": 0',
            '"label": 1',  # Identical values are still ambiguous input.
            '"la\\u0062el": 0',
            '"eml": "private-missing.eml"',
            '"analysis": null, "analysis": {}',
            '"analysis_result": "private-missing.json", "analysis_result": "analysis.json"',
            '"analysis": {"url_analysis": {"total_urls": 99, "total_urls": 0}}',
            '"source": [{"private-duplicate-key": 1, "private-duplicate-key": 2}]',
        )
        (self.root / "analysis.json").write_text("{}")
        for extra in cases:
            with self.subTest(extra=extra, existing_report=existing_report):
                self.manifest.write_text(json.dumps(self.rows[0]) + "\n\n{" + extra + ", "
                                         + json.dumps(self.rows[1])[1:] + "\n")
                if existing_report:
                    self.report.write_bytes(b"previous report must survive")
                before = {p: p.read_bytes() for p in self.root.iterdir()}
                completed = self.run_evaluation()
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assert_rejected(completed, "invalid manifest JSON")
                self.assertNotIn("private-duplicate-key", completed.stdout + completed.stderr)
                self.assertNotIn("private-missing", completed.stdout + completed.stderr)
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_duplicate_manifest_keys_do_not_create_report(self):
        self.check_duplicate_manifest_keys(existing_report=False)

    def test_duplicate_manifest_keys_preserve_report_and_inputs(self):
        self.check_duplicate_manifest_keys(existing_report=True)

    def test_duplicate_analysis_file_keys_are_rejected(self):
        self.add("first independent body")
        self.add("second independent body")
        analysis = self.root / "private-analysis.json"
        self.rows[1]["analysis_result"] = analysis.name
        self.manifest.write_text("\n\n".join(json.dumps(r) for r in self.rows))
        for existing_report in (False, True):
            for raw in (
                '{"url_analysis": {}, "url_analysis": {}}',
                '{"url_analysis": {"total_urls": 1, "total_urls": 0}}',
                '{"private-duplicate-key": [{"x": 1, "\\u0078": 2}]}',
            ):
                with self.subTest(raw=raw, existing_report=existing_report):
                    analysis.write_text(raw)
                    if existing_report:
                        self.report.write_bytes(b"previous report must survive")
                    before = {p: p.read_bytes() for p in self.root.iterdir()}
                    completed = self.run_evaluation()
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    self.assert_rejected(completed, "invalid or unavailable analysis_result")
                    self.assertNotIn("private-duplicate-key", completed.stdout + completed.stderr)
                    self.assertNotIn("private-analysis", completed.stdout + completed.stderr)
                    self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_same_key_in_separate_objects_remains_valid(self):
        self.add("first independent body")
        self.add("second independent body")
        evidence = {"left": {"same": 1}, "right": {"same": 2},
                    "items": [{"same": 3}, {"same": 4}]}
        analysis = self.root / "analysis.json"
        analysis.write_text(json.dumps(evidence))
        self.rows[0]["analysis"] = evidence
        self.rows[1]["analysis_result"] = analysis.name
        self.manifest.write_text("\n\n".join(json.dumps(r) for r in self.rows))
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)

    def check_nonfinite_json(self, *, analysis_file):
        self.add("first independent body")
        self.add("second independent body")
        analysis = self.root / "private-analysis.json"
        fragments = [
            '{"url_analysis": {"total_urls": ' + token + '}}'
            for token in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999")
        ] + ['{"private-field": [{"x": NaN}]}',
             '{"private-field": [{"x": 1e999}]}']
        for existing_report in (False, True):
            for fragment in fragments:
                with self.subTest(fragment=fragment, existing_report=existing_report):
                    row = dict(self.rows[1])
                    if analysis_file:
                        analysis.write_text(fragment, encoding="utf-8")
                        row["analysis_result"] = analysis.name
                        raw_row = json.dumps(row)
                        reason = "invalid or unavailable analysis_result"
                    else:
                        raw_row = json.dumps(row)[:-1] + ', "analysis": ' + fragment + '}'
                        reason = "invalid manifest JSON"
                    self.manifest.write_text(json.dumps(self.rows[0]) + "\n\n" + raw_row)
                    if existing_report:
                        self.report.write_bytes(b"previous report must survive")
                    before = {p: p.read_bytes() for p in self.root.iterdir()}
                    completed = self.run_evaluation()
                    self.assertEqual(completed.returncode, 1, completed.stderr)
                    self.assert_rejected(completed, reason)
                    for private in ("private-field", "private-analysis"):
                        self.assertNotIn(private, completed.stdout + completed.stderr)
                    self.assertEqual(before, {p: p.read_bytes() for p in self.root.iterdir()})

    def test_nonfinite_manifest_numbers_are_rejected_without_writes(self):
        self.check_nonfinite_json(analysis_file=False)

    def test_nonfinite_analysis_file_numbers_are_rejected_without_writes(self):
        self.check_nonfinite_json(analysis_file=True)

    def test_finite_json_numbers_and_numeric_strings_remain_valid(self):
        self.add("first independent body")
        self.add("second independent body")
        evidence = {"url_analysis": {"total_urls": 1e300},
                    "metadata": [-1e300, 0.0, 1e-300, "NaN", "Infinity", "1e999"]}
        analysis = self.root / "analysis.json"
        analysis.write_text(json.dumps(evidence))
        self.rows[0]["analysis"] = evidence
        self.rows[1]["analysis_result"] = analysis.name
        self.manifest.write_text("\n\n".join(json.dumps(r) for r in self.rows))
        completed = self.run_evaluation()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(self.report.read_text())["observed"]["rows"], 2)


if __name__ == "__main__":
    unittest.main()
