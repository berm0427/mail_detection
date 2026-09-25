"""Reject invalid gate criteria before costly training or artifact writes."""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import run_evidence_candidate_pipeline as pipeline


INVALID = {
    "--external-min-rows": ("0", "-1", "1.5", "nan"),
    **{flag: ("nan", "inf", "-inf", "1e999", "-0.01", "1.01", "invalid")
       for flag in ("--external-min-auc", "--external-max-fpr", "--external-min-recall")},
}


class CandidatePipelineGateArgsTests(unittest.TestCase):
    def argv(self, root, *options):
        return ["pipeline", str(root / "training.jsonl"), str(root / "external.jsonl"),
                str(root / "output" / "candidate.json"), str(root / "approved.json"),
                "--model-id", "gate-args-fixture", *options]

    def test_invalid_criteria_preserve_existing_artifacts_before_preflight(self):
        for flag, values in INVALID.items():
            for value in values:
                with self.subTest(flag=flag, value=value), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    output = root / "output"
                    output.mkdir()
                    for name in ("candidate.json", "candidate.metrics.json",
                                 "candidate.external.json", "candidate.pipeline.json"):
                        (output / name).write_bytes(b"existing artifact")
                    for name in ("training.jsonl", "external.jsonl", "approved.json"):
                        (root / name).write_bytes(b"existing input or approved artifact")
                    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
                    entries = set(root.rglob("*"))

                    def train(command):
                        # Model the trainer's writes on internal-gate failure.
                        (output / "candidate.metrics.json").write_bytes(b"new training metrics")
                        return subprocess.CompletedProcess(command, 2)

                    with patch.object(sys, "argv", self.argv(root, f"{flag}={value}")), \
                            patch.object(pipeline, "check_independence", return_value={"passed": True}) as check, \
                            patch.object(pipeline, "run", side_effect=train) as runner, \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()) as stderr:
                        with self.assertRaises(SystemExit) as caught:
                            pipeline.main()
                    self.assertEqual(caught.exception.code, 2)
                    self.assertEqual(before, {p: p.read_bytes() for p in root.rglob("*") if p.is_file()})
                    self.assertEqual(entries, set(root.rglob("*")))
                    self.assertIn(flag, stderr.getvalue())
                    check.assert_not_called()
                    runner.assert_not_called()

    def test_invalid_criteria_real_cli_creates_no_output_directory(self):
        # No manifests exist: argument rejection must precede input access.
        for flag, values in INVALID.items():
            for value in values:
                with self.subTest(flag=flag, value=value), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    result = subprocess.run(
                        [sys.executable, "-B", "-S", "-m", "tools.run_evidence_candidate_pipeline",
                         *self.argv(root, f"{flag}={value}")[1:]],
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(flag, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(root.iterdir()), [])

    def test_valid_defaults_and_boundaries_are_forwarded_to_evaluator(self):
        for options, expected in (
            ([], ("100", "0.75", "0.15", "0.65")),
            (["--external-min-rows=1", "--external-min-auc=0",
              "--external-max-fpr=1", "--external-min-recall=0"], ("1", "0.0", "1.0", "0.0")),
            (["--external-min-rows=150", "--external-min-auc=1",
              "--external-max-fpr=0", "--external-min-recall=1"], ("150", "1.0", "0.0", "1.0")),
        ):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate = root / "output" / "candidate.json"

                def run(command):
                    if "email_analyzer.train_evidence_ml" in command:
                        candidate.write_bytes(b"temporary candidate")
                        return subprocess.CompletedProcess(command, 0)
                    self.assertIn("email_analyzer.evaluate_evidence_ml", command)
                    for flag, value in zip(("--min-rows", "--min-auc", "--max-fpr", "--min-recall"), expected):
                        self.assertEqual(command[command.index(flag) + 1], value)
                    return subprocess.CompletedProcess(command, 2)

                with patch.object(sys, "argv", self.argv(root, *options)), \
                        patch.object(pipeline, "check_independence", return_value={"passed": True}) as check, \
                        patch.object(pipeline, "run", side_effect=run) as runner, \
                        contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        pipeline.main()
                self.assertEqual(caught.exception.code, 2)
                check.assert_called_once()
                self.assertEqual(runner.call_count, 2)
                self.assertFalse((root / "approved.json").exists())


if __name__ == "__main__":
    unittest.main()
