import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from email_analyzer.manifest_independence import check_independence
from tools import run_evidence_candidate_pipeline as pipeline


class ManifestIndependenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.training = self.root / "training" / "manifest.jsonl"
        self.external = self.root / "external" / "manifest.jsonl"
        self.training.parent.mkdir()
        self.external.parent.mkdir()
        self.train_row = {"eml": "message.eml", "label": 0, "group_id": "campaign-A", "split": "train"}
        self.external_row = {"eml": "message.eml", "label": 1}
        self.write_eml(self.training.parent / "message.eml", "Training body", subject="Original")
        self.write_eml(self.external.parent / "message.eml", "Independent body", subject="External")
        self.save()

    def write_eml(self, path, body, subject="Notice", subtype="plain", cte="quoted-printable"):
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = "synthetic@example.org"
        message.set_content(body, subtype=subtype, cte=cte)
        path.write_bytes(message.as_bytes())

    def save(self):
        self.training.write_text(json.dumps(self.train_row) + "\n", encoding="utf-8")
        self.external.write_text(json.dumps(self.external_row) + "\n", encoding="utf-8")

    def check(self):
        return check_independence(self.training, self.external)

    def test_nonfinite_json_rejected_before_eml_reads_in_both_roles(self):
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            for token in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
                for fragment in ('"private-score":' + token,
                                 '"analysis":{"nested":[{"private-score":' + token + '}]}'):
                    with self.subTest(role=role, token=token, nested="analysis" in fragment):
                        self.save()
                        path.write_text('\n\n' + json.dumps(row)[:-1] + ',' + fragment + '}\n',
                                        encoding="utf-8")
                        with patch("email_analyzer.manifest_independence._fingerprints") as read_eml:
                            with self.assertRaisesRegex(ValueError,
                                    f"^invalid JSON in {role} manifest at line 3$"):
                                self.check()
                            read_eml.assert_not_called()

    def test_finite_json_numbers_and_nonfinite_strings_preserve_hashes(self):
        for path, row in ((self.training, self.train_row), (self.external, self.external_row)):
            row = dict(row, analysis={"values":[0, -1, 1.5, 1e308, -1e308, 1e-300],
                                      "strings":["NaN", "Infinity", "-Infinity", "1e999"]})
            path.write_text('\n' + json.dumps(row) + '\n', encoding="utf-8")
        report = self.check()
        self.assertTrue(report["passed"])
        for role, path in (("training", self.training), ("external", self.external)):
            self.assertEqual(report[role + "_rows"], 1)
            self.assertEqual(report[role + "_manifest_sha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())

    def test_nonfinite_json_cli_redacts_details_and_preserves_inputs(self):
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            for token in ("NaN", "1e999"):
                with self.subTest(role=role, token=token):
                    self.save()
                    path.write_text('\n\n' + json.dumps(row)[:-1] +
                                    ',"private-key":{"private-value":' + token + '}}\n',
                                    encoding="utf-8")
                    before = {p:p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
                    completed = subprocess.run([
                        sys.executable, "-B", "-S", "-m", "email_analyzer.manifest_independence",
                        str(self.training), str(self.external),
                    ], capture_output=True, text=True, timeout=10)
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertEqual(json.loads(completed.stdout), {
                        "passed":False, "error":f"invalid JSON in {role} manifest at line 3"})
                    self.assertEqual(completed.stderr, "")
                    self.assertEqual(before, {p:p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_nonfinite_json_pipeline_stops_before_training_and_preserves_artifacts(self):
        candidate, approved = self.root / "candidate.json", self.root / "approved.json"
        for path in (candidate, approved, candidate.with_suffix(".metrics.json"),
                     candidate.with_suffix(".external.json")):
            path.write_bytes(b"existing artifact")
        argv = ["pipeline", str(self.training), str(self.external), str(candidate),
                str(approved), "--model-id", "synthetic-nonfinite-test"]
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            for token in ("Infinity", "-1e999"):
                with self.subTest(role=role, token=token):
                    self.save()
                    path.write_text('\n\n' + json.dumps(row)[:-1] +
                                    ',"analysis":{"private-score":' + token + '}}\n',
                                    encoding="utf-8")
                    status_path = candidate.with_suffix(".pipeline.json")
                    before = {p:p.read_bytes() for p in self.root.rglob("*")
                              if p.is_file() and p != status_path}
                    with patch.object(sys, "argv", argv), patch.object(pipeline, "run") as run:
                        run.return_value = subprocess.CompletedProcess([], 3)
                        with self.assertRaises(SystemExit) as caught:
                            pipeline.main()
                        run.assert_not_called()
                        self.assertEqual(caught.exception.code, 2)
                    status = json.loads(status_path.read_text())
                    self.assertEqual(status["input_independence"], {
                        "passed":False, "error":f"invalid JSON in {role} manifest at line 3"})
                    self.assertFalse(status["trained"])
                    self.assertFalse(status["approved"])
                    self.assertNotIn("training_returncode", status)
                    self.assertEqual(before, {p:p.read_bytes() for p in self.root.rglob("*")
                                             if p.is_file() and p != status_path})

    def test_duplicate_json_keys_rejected_in_both_manifest_roles(self):
        fragments = (
            '"label":0,"label":1',
            '"label":1,"label":1',
            '"la\\u0062el":0,"label":1',
            '"eml":"private-missing.eml","eml":"message.eml"',
            '"group_id":"private-campaign","group_id":"distinct"',
            '"split":"test","split":"train"',
            '"analysis":{"private-key":0,"private-key":1}',
            '"metadata":[{"private-key":0,"private-key":1}]',
        )
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            for fragment in fragments:
                with self.subTest(role=role, fragment=fragment):
                    self.save()
                    # Do not introduce an extra literal duplicate that could
                    # mask a failure to recognize Unicode-escaped key aliases.
                    fragment_keys = json.loads('{' + fragment + '}')
                    base_row = {key:value for key, value in row.items() if key not in fragment_keys}
                    path.write_text('\n\n' + json.dumps(base_row)[:-1] + ',' + fragment + '}\n',
                                    encoding="utf-8")
                    with patch("email_analyzer.manifest_independence._fingerprints") as read_eml:
                        with self.assertRaisesRegex(ValueError,
                                f"^invalid JSON in {role} manifest at line 3$"):
                            self.check()
                        read_eml.assert_not_called()

    def test_same_keys_in_separate_objects_and_json_strings_remain_valid(self):
        for path, row in ((self.training, self.train_row), (self.external, self.external_row)):
            row = dict(row, metadata=[{"key":0}, {"key":1}],
                       analysis={"nested":{"key":2}}, note='{"label":0,"label":1}')
            path.write_text(json.dumps(row) + '\n', encoding="utf-8")
        report = self.check()
        self.assertTrue(report["passed"])
        for role, path in (("training", self.training), ("external", self.external)):
            self.assertEqual(report[role + "_rows"], 1)
            self.assertEqual(report[role + "_manifest_sha256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())

    def test_duplicate_key_cli_redacts_details_and_preserves_inputs(self):
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            with self.subTest(role=role):
                self.save()
                path.write_text('\n\n' + json.dumps(row)[:-1] +
                                ',"private-key":"private-value","private-key":0}\n',
                                encoding="utf-8")
                before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
                completed = subprocess.run([
                    sys.executable, "-B", "-S", "-m", "email_analyzer.manifest_independence",
                    str(self.training), str(self.external),
                ], capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(json.loads(completed.stdout), {
                    "passed":False, "error":f"invalid JSON in {role} manifest at line 3"})
                self.assertEqual(completed.stderr, "")
                self.assertEqual(before, {p:p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_duplicate_key_pipeline_stops_before_training_and_preserves_artifacts(self):
        candidate, approved = self.root / "candidate.json", self.root / "approved.json"
        for path in (candidate, approved, candidate.with_suffix(".metrics.json"),
                     candidate.with_suffix(".external.json")):
            path.write_bytes(b"existing artifact")
        argv = ["pipeline", str(self.training), str(self.external), str(candidate),
                str(approved), "--model-id", "synthetic-duplicate-key-test"]
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            with self.subTest(role=role):
                self.save()
                path.write_text('\n\n' + json.dumps(row)[:-1] + ',"label":0,"label":1}\n',
                                encoding="utf-8")
                before = {p:p.read_bytes() for p in self.root.rglob("*")
                          if p.is_file() and p != candidate.with_suffix(".pipeline.json")}
                with patch.object(sys, "argv", argv), patch.object(pipeline, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], 3)
                    with self.assertRaises(SystemExit) as caught:
                        pipeline.main()
                    self.assertEqual(caught.exception.code, 2)
                    run.assert_not_called()
                status = json.loads(candidate.with_suffix(".pipeline.json").read_text())
                self.assertEqual(status["input_independence"], {
                    "passed":False, "error":f"invalid JSON in {role} manifest at line 3"})
                self.assertFalse(status["trained"])
                self.assertFalse(status["approved"])
                self.assertNotIn("training_returncode", status)
                self.assertEqual(before, {p:p.read_bytes() for p in self.root.rglob("*")
                                         if p.is_file() and p != candidate.with_suffix(".pipeline.json")})

    def test_independent_relative_paths_and_missing_group_coverage(self):
        report = self.check()
        self.assertTrue(report["passed"])
        self.assertEqual(report["training_rows"], 1)
        self.assertEqual(report["external_rows"], 1)
        self.assertEqual(report["external_rows_without_group_id"], 1)
        self.assertEqual(len(report["training_manifest_sha256"]), 64)

    def test_distinct_groups_and_absolute_eml_path(self):
        self.external_row.update(group_id="campaign-B", eml=str(self.external.parent / "message.eml"))
        self.save()
        self.assertEqual(self.check()["external_rows_without_group_id"], 0)

    def test_unicode_json_strings_and_crlf_preserve_rows_and_manifest_hashes(self):
        for separator in ("\u0085", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                for path, row in ((self.training, self.train_row),
                                  (self.external, self.external_row)):
                    content = json.dumps(dict(row, source="fixture" + separator + "metadata"),
                                         ensure_ascii=False).encode("utf-8")
                    path.write_bytes(b"\r\n" + content + b"\r\n\r\n")
                report = self.check()
                self.assertTrue(report["passed"])
                for role, path in (("training", self.training), ("external", self.external)):
                    self.assertEqual(report[role + "_rows"], 1)
                    self.assertEqual(report[role + "_manifest_sha256"],
                                     hashlib.sha256(path.read_bytes()).hexdigest())

    def test_json_error_after_unicode_string_uses_physical_line(self):
        for role, path, row in (("training", self.training, self.train_row),
                                ("external", self.external, self.external_row)):
            with self.subTest(role=role):
                self.save()
                valid = json.dumps(dict(row, source="private\u2028metadata"), ensure_ascii=False)
                path.write_text(valid + "\n\nprivate malformed JSON\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError,
                                           f"^invalid JSON in {role} manifest at line 3$"):
                    self.check()

    def test_invalid_utf8_cli_has_safe_physical_line_and_preserves_inputs(self):
        for role, path in (("training", self.training), ("external", self.external)):
            with self.subTest(role=role):
                self.save()
                path.write_bytes(path.read_bytes() + b'\n{"private-data": "\xff"}\n')
                before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
                completed = subprocess.run([
                    sys.executable, "-B", "-S", "-m", "email_analyzer.manifest_independence",
                    str(self.training), str(self.external),
                ], capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(json.loads(completed.stdout), {
                    "passed": False, "error": f"invalid JSON in {role} manifest at line 3"})
                self.assertEqual(completed.stderr, "")
                self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_unicode_group_overlap_remains_rejected(self):
        group = "private\u2028campaign"
        for path, row in ((self.training, self.train_row), (self.external, self.external_row)):
            path.write_text(json.dumps(dict(row, group_id=group), ensure_ascii=False) + "\n",
                            encoding="utf-8")
        with self.assertRaisesRegex(ValueError,
                                   "^group_id overlap with training manifest at external line 1$"):
            self.check()

    def test_shared_group_rejected_against_every_training_split(self):
        for split in ("train", "validation", "test"):
            with self.subTest(split=split):
                self.train_row["split"] = split
                self.external_row["group_id"] = " campaign-A "
                self.save()
                with self.assertRaisesRegex(ValueError, "group_id overlap"):
                    self.check()

    def test_raw_copy_rejected_even_with_different_path_group_and_label(self):
        (self.external.parent / "message.eml").write_bytes((self.training.parent / "message.eml").read_bytes())
        self.external_row["group_id"] = "campaign-B"
        for split in ("train", "validation", "test"):
            with self.subTest(split=split):
                self.train_row["split"] = split
                self.save()
                with self.assertRaisesRegex(ValueError, "raw EML overlap"):
                    self.check()

    def test_changed_subject_encoding_case_and_whitespace_do_not_hide_copy(self):
        self.write_eml(self.external.parent / "message.eml", "  TRAINING\n\tBODY  ",
                       subject="Completely different subject", cte="base64")
        with self.assertRaisesRegex(ValueError, "normalized body overlap"):
            self.check()

    def test_html_visible_body_matches_plain_text(self):
        self.write_eml(self.external.parent / "message.eml",
                       "<html><head><title>ignored</title></head><body><p>Training BODY</p></body></html>",
                       subtype="html")
        with self.assertRaisesRegex(ValueError, "normalized body overlap"):
            self.check()

    def test_distinct_long_suffixes_are_not_truncated_to_false_duplicates(self):
        prefix = "long shared prefix " * 6000
        self.write_eml(self.training.parent / "message.eml", prefix + "first")
        self.write_eml(self.external.parent / "message.eml", prefix + "second")
        self.assertTrue(self.check()["passed"])

    def test_empty_bodies_do_not_match_by_empty_normalized_text(self):
        self.write_eml(self.training.parent / "message.eml", "", subject="First")
        self.write_eml(self.external.parent / "message.eml", "", subject="Second")
        self.assertTrue(self.check()["passed"])

    def test_empty_or_invalid_manifests_fail_without_echoing_input(self):
        secret = "private-fixture-do-not-echo"
        for content in ("\n", secret, "[]", json.dumps({"eml": secret, "label": True}),
                        json.dumps({"eml": secret, "label": 1, "group_id": []})):
            with self.subTest(content_type=content[:1]):
                self.external.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError) as caught:
                    self.check()
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn(str(self.root), str(caught.exception))

    def test_missing_input_is_redacted_and_json_error_has_physical_line_number(self):
        self.external_row["eml"] = "private-missing-file.eml"
        self.save()
        with self.assertRaisesRegex(ValueError, "cannot read/parse external EML at line 1") as caught:
            self.check()
        self.assertNotIn("private", str(caught.exception))
        self.external.write_text("\n\nprivate malformed JSON\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "external manifest at line 3"):
            self.check()

    def test_invalid_training_split_or_group_is_rejected(self):
        for field, value in (("split", "unknown"), ("group_id", ""), ("group_id", None)):
            original = self.train_row[field]
            self.train_row[field] = value
            self.save()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.check()
            self.train_row[field] = original

    def test_cli_runs_without_site_packages_and_reports_only_metadata(self):
        command = [sys.executable, "-B", "-S", "-m", "email_analyzer.manifest_independence",
                   str(self.training), str(self.external)]
        good = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertTrue(json.loads(good.stdout)["passed"])
        self.external_row["group_id"] = "campaign-A"
        self.save()
        bad = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(bad.returncode, 2, bad.stderr)
        self.assertFalse(json.loads(bad.stdout)["passed"])
        for private in ("campaign-A", "Training body", str(self.root)):
            self.assertNotIn(private, bad.stdout + bad.stderr)

    def test_pipeline_blocks_leak_before_training_and_preserves_existing_artifacts(self):
        self.external_row["group_id"] = "campaign-A"
        self.save()
        candidate, approved = self.root / "candidate.json", self.root / "approved.json"
        candidate.write_bytes(b"existing candidate")
        approved.write_bytes(b"existing approved")
        command = [sys.executable, "-B", "-S", "-m", "tools.run_evidence_candidate_pipeline",
                   str(self.training), str(self.external), str(candidate), str(approved),
                   "--model-id", "synthetic-preflight-test"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        status = json.loads(candidate.with_suffix(".pipeline.json").read_text())
        self.assertFalse(status["input_independence"]["passed"])
        self.assertFalse(status["trained"])
        self.assertFalse(status["approved"])
        self.assertFalse(status["production_config_changed"])
        self.assertNotIn("training_returncode", status)
        self.assertNotIn("external_returncode", status)
        self.assertEqual(candidate.read_bytes(), b"existing candidate")
        self.assertEqual(approved.read_bytes(), b"existing approved")
        self.assertFalse(candidate.with_suffix(".external.json").exists())

    def test_independent_inputs_continue_to_existing_training_stage(self):
        candidate = self.root / "candidate.json"
        argv = ["pipeline", str(self.training), str(self.external), str(candidate),
                str(self.root / "approved.json"), "--model-id", "synthetic-preflight-test"]
        with patch.object(sys, "argv", argv), patch.object(pipeline, "run") as run:
            # Only the process boundary is replaced; preflight uses real files.
            run.return_value = subprocess.CompletedProcess([], 3)
            with self.assertRaises(SystemExit) as caught:
                pipeline.main()
            self.assertEqual(caught.exception.code, 3)
            run.assert_called_once()
            self.assertIn("email_analyzer.train_evidence_ml", run.call_args.args[0])
        status = json.loads(candidate.with_suffix(".pipeline.json").read_text())
        self.assertTrue(status["input_independence"]["passed"])
        self.assertFalse(status["approved"])

    def append_external(self, *, body=None, subject="Changed subject", label=0, **kwargs):
        other = self.external.parent / "second.eml"
        if body is None:
            other.write_bytes((self.external.parent / "message.eml").read_bytes())
        else:
            self.write_eml(other, body, subject=subject, **kwargs)
        row = dict(self.external_row, eml=other.name, label=label, group_id="other-campaign")
        # Use physical line 3 to cover blank-line diagnostics too.
        with self.external.open("a", encoding="utf-8") as stream:
            stream.write("\n" + json.dumps(row) + "\n")

    def test_external_raw_duplicates_rejected_even_with_conflicting_labels(self):
        self.append_external()
        with self.assertRaisesRegex(ValueError, "raw EML duplicate within external manifest at line 3"):
            self.check()

    def test_external_normalized_duplicates_ignore_subject_encoding_and_label(self):
        self.append_external(body="  INDEPENDENT\n\tBODY  ", cte="base64")
        with self.assertRaisesRegex(ValueError, "normalized body duplicate within external manifest at line 3"):
            self.check()

    def test_external_html_plain_duplicates_are_rejected(self):
        self.append_external(body="<p>Independent BODY</p>", subtype="html")
        with self.assertRaisesRegex(ValueError, "normalized body duplicate within external"):
            self.check()

    def test_external_distinct_messages_in_one_campaign_remain_allowed(self):
        self.external_row["group_id"] = "other-campaign"
        self.save()
        self.append_external(body="Different legitimate message in the same campaign")
        self.assertEqual(self.check()["external_rows"], 2)

    def test_external_empty_bodies_only_match_by_raw_bytes(self):
        self.write_eml(self.external.parent / "message.eml", "", subject="First")
        self.append_external(body="", subject="Second")
        self.assertTrue(self.check()["passed"])

    def test_external_long_distinct_suffixes_remain_independent(self):
        prefix = "shared external prefix " * 6000
        self.write_eml(self.external.parent / "message.eml", prefix + "first")
        self.append_external(body=prefix + "second")
        self.assertTrue(self.check()["passed"])

    def test_external_duplicate_cli_is_redacted_and_preserves_inputs(self):
        self.append_external(body="INDEPENDENT body", cte="base64")
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        completed = subprocess.run([
            sys.executable, "-B", "-S", "-m", "email_analyzer.manifest_independence",
            str(self.training), str(self.external),
        ], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertFalse(json.loads(completed.stdout)["passed"])
        for private in ("INDEPENDENT", "other-campaign", "second.eml", str(self.root)):
            self.assertNotIn(private, completed.stdout + completed.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_pipeline_blocks_external_duplicates_before_training(self):
        self.append_external(body="INDEPENDENT body", cte="base64")
        candidate, approved = self.root / "candidate.json", self.root / "approved.json"
        candidate.write_bytes(b"existing candidate")
        approved.write_bytes(b"existing approved")
        argv = ["pipeline", str(self.training), str(self.external), str(candidate),
                str(approved), "--model-id", "synthetic-duplicate-test"]
        with patch.object(sys, "argv", argv), patch.object(pipeline, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 3)
            with self.assertRaises(SystemExit) as caught:
                pipeline.main()
            self.assertEqual(caught.exception.code, 2)
            run.assert_not_called()
        status = json.loads(candidate.with_suffix(".pipeline.json").read_text())
        self.assertFalse(status["input_independence"]["passed"])
        self.assertFalse(status["trained"])
        self.assertFalse(status["approved"])
        self.assertFalse(status["production_config_changed"])
        self.assertNotIn("training_returncode", status)
        self.assertNotIn("external_returncode", status)
        self.assertEqual(candidate.read_bytes(), b"existing candidate")
        self.assertEqual(approved.read_bytes(), b"existing approved")
        self.assertFalse(candidate.with_suffix(".external.json").exists())


if __name__ == "__main__":
    unittest.main()
