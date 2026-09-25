import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from email_analyzer.manifest_independence import check_independence
from tools.port_evidence_manifest import port_manifest


class PortManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.local = self.root / "local"
        self.local.mkdir()
        self.source = self.local / "source.jsonl"
        self.outdir = self.root / "copies"
        self.outdir.mkdir()
        self.output = self.outdir / "portable.jsonl"
        self.eml = self.local / "메일.eml"
        self.eml.write_bytes(b"Subject: Synthetic\n\nSynthetic training body\n")
        self.analysis = self.local / "analysis.json"
        self.analysis.write_text("{}", encoding="utf-8")
        self.row = {"eml": r"C:\old\dataset\메일.eml",
                    "analysis_result": r"C:\old\dataset\analysis.json",
                    "label": 0, "split": "train", "group_id": "synthetic-A",
                    "extra": {"retained": True}}
        self.save()

    def save(self, rows=None):
        self.source.write_text("\n".join(json.dumps(x) for x in (rows or [self.row])) + "\n",
                               encoding="utf-8")

    def port(self, **kwargs):
        return port_manifest(self.source, self.output, local_root=self.local,
                             source_root=kwargs.pop("source_root", r"C:\old\dataset"), **kwargs)

    def assert_rejected(self, pattern):
        with self.assertRaisesRegex(ValueError, pattern) as caught:
            self.port()
        for private in (str(self.root), "메일", "synthetic-A", "private"):
            self.assertNotIn(private, str(caught.exception))
        self.assertFalse(self.output.exists())

    def test_windows_mapping_preserves_source_metadata_and_both_inputs(self):
        before = {p: p.read_bytes() for p in (self.source, self.eml, self.analysis)}
        report = self.port()
        converted = json.loads(self.output.read_text())
        self.assertEqual(report["validated_paths"], {"eml": 1, "analysis_result": 1})
        for field, target in (("eml", self.eml), ("analysis_result", self.analysis)):
            self.assertFalse(Path(converted[field]).is_absolute())
            self.assertEqual((self.output.parent / converted[field]).resolve(), target)
        for key in ("label", "split", "group_id", "extra"):
            self.assertEqual(converted[key], self.row[key])
        for path, original in before.items():
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual(report["source_manifest_sha256"], hashlib.sha256(before[self.source]).hexdigest())
        self.assertEqual(report["output_manifest_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())

    def test_posix_root_mapping(self):
        self.row.update(eml="/old/dataset/메일.eml", analysis_result="/old/dataset/analysis.json")
        self.save()
        self.assertTrue(self.port(source_root="/old/dataset")["passed"])

    def test_windows_case_insensitive_root_and_forward_slashes(self):
        self.row.update(eml="c:/OLD/DATASET/메일.eml", analysis_result="c:/OLD/DATASET/analysis.json")
        self.save()
        self.assertTrue(self.port()["passed"])

    def test_unc_root_mapping(self):
        self.row.update(eml=r"\\server\share\dataset\메일.eml",
                        analysis_result=r"\\server\share\dataset\analysis.json")
        self.save()
        self.assertTrue(self.port(source_root=r"\\server\share\dataset")["passed"])

    def test_relative_paths_resolve_from_source_not_destination_or_cwd(self):
        self.row.update(eml=".\\메일.eml", analysis_result="./analysis.json")
        self.save()
        self.assertTrue(self.port()["passed"])
        row = json.loads(self.output.read_text())
        self.assertEqual((self.output.parent / row["eml"]).resolve(), self.eml)

    def test_external_eml_only_and_training_inline_analysis(self):
        del self.row["analysis_result"]
        self.row["analysis"] = {}
        self.save()
        self.assertTrue(self.port()["passed"])
        second = self.outdir / "external.jsonl"
        self.row.pop("analysis")
        self.row.pop("split")
        self.row.pop("group_id")
        self.save()
        report = port_manifest(self.source, second, local_root=self.local,
                               source_root=r"C:\old\dataset", role="external")
        self.assertEqual(report["validated_paths"]["analysis_result"], 0)

    def test_missing_training_analysis_is_not_silently_empty(self):
        del self.row["analysis_result"]
        self.save()
        self.assert_rejected("missing analysis input")

    def test_invalid_paths_and_root_prefix_collision_are_rejected(self):
        for path in (r"C:\old\dataset-extra\메일.eml", r"D:\old\dataset\메일.eml",
                     r"C:메일.eml", r"\메일.eml", r"C:\old\dataset\..\메일.eml",
                     r"C:\old\dataset\메일.eml:private", "private\x00.eml", 123, ""):
            with self.subTest(path_kind=type(path).__name__):
                self.row["eml"] = path
                self.save()
                self.assert_rejected("invalid")

    def test_relative_escape_and_symlink_escape_are_rejected(self):
        outside = self.root / "private.eml"
        outside.write_bytes(self.eml.read_bytes())
        self.row["eml"] = "../private.eml"
        self.save()
        self.assert_rejected("invalid or unavailable eml")
        (self.local / "link.eml").symlink_to(outside)
        self.row["eml"] = r"C:\old\dataset\link.eml"
        self.save()
        self.assert_rejected("invalid or unavailable eml")

    def test_missing_files_and_directories_are_rejected(self):
        for field, value in (("eml", "missing.eml"), ("analysis_result", "missing.json"),
                             ("eml", "."), ("analysis_result", ".")):
            with self.subTest(field=field):
                row = dict(self.row, **{field: value})
                self.save([row])
                self.assert_rejected("invalid or unavailable " + field)

    def test_invalid_analysis_json_or_inline_analysis_is_rejected(self):
        for content in ("[]", "null", "private malformed JSON", '"private"'):
            self.analysis.write_text(content)
            self.assert_rejected("invalid or unavailable analysis_result")
        self.row["analysis"] = []
        self.save()
        self.assert_rejected("invalid analysis")

    def test_all_rows_checked_before_output_creation_and_line_numbers_preserved(self):
        second = dict(self.row, analysis_result="private-missing.json")
        self.source.write_text(json.dumps(self.row) + "\n\n" + json.dumps(second))
        self.assert_rejected("analysis_result at training line 3")

    def test_existing_output_and_source_cannot_be_overwritten(self):
        self.output.write_bytes(b"keep existing")
        with self.assertRaisesRegex(ValueError, "output already exists"):
            self.port()
        self.assertEqual(self.output.read_bytes(), b"keep existing")
        before = self.source.read_bytes()
        with self.assertRaisesRegex(ValueError, "output already exists"):
            port_manifest(self.source, self.source, source_root=r"C:\old\dataset", local_root=self.local)
        self.assertEqual(self.source.read_bytes(), before)

    def test_dangling_output_symlink_is_not_followed(self):
        target = self.root / "private-new.jsonl"
        self.output.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "output already exists"):
            self.port()
        self.assertFalse(target.exists())

    def test_invalid_source_roots_are_rejected(self):
        for root in ("relative", "C:relative", r"C:\old\..\dataset", "/old/../dataset"):
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, "source root"):
                self.port(source_root=root)
        self.assertFalse(self.output.exists())

    def test_ported_manifest_works_with_existing_independence_guard(self):
        self.port()
        eml = self.local / "external.eml"
        eml.write_bytes(b"Subject: Other\n\nIndependent synthetic body\n")
        external = self.local / "external.jsonl"
        external.write_text(json.dumps({"eml": eml.name, "label": 1}))
        self.assertTrue(check_independence(self.output, external)["passed"])

    def test_cli_without_site_packages_and_redacted_failure(self):
        cmd = [sys.executable, "-B", "-S", "-m", "tools.port_evidence_manifest",
               str(self.source), str(self.output), "--source-root", r"C:\old\dataset",
               "--local-root", str(self.local)]
        good = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertTrue(json.loads(good.stdout)["passed"])
        bad = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertEqual(bad.returncode, 2, bad.stderr)
        self.assertFalse(json.loads(bad.stdout)["passed"])
        for result in (good, bad):
            self.assertNotIn(str(self.root), result.stdout + result.stderr)
            self.assertNotIn("synthetic-A", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
