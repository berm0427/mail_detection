import json
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path


class CandidatePipelineTests(unittest.TestCase):
    def test_external_failure_never_creates_approved_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); training = []; external = []
            for split in ("train", "validation", "test"):
                for index in range(6):
                    for label in (0, 1):
                        stem = f"{split}-{index}-{label}"
                        message = EmailMessage(); message["Subject"] = "bad" if label else "good"
                        message.set_content(("credential action " if label else "ordinary notice ") + stem)
                        eml = root / f"{stem}.eml"; eml.write_bytes(message.as_bytes())
                        result = root / f"{stem}.json"; result.write_text("{}", encoding="utf-8")
                        training.append({"eml": eml.name, "analysis_result": result.name,
                                         "label": label, "split": split, "group_id": stem})
            # Deliberately reverse the independent labels so internal success
            # cannot authorize the candidate.
            for index, label in enumerate((0, 1, 0, 1)):
                message = EmailMessage(); message["Subject"] = "bad" if label == 0 else "good"
                message.set_content(f"external {index}")
                eml = root / f"external-{index}.eml"; eml.write_bytes(message.as_bytes())
                external.append({"eml": eml.name, "label": label})
            train_manifest = root / "train.jsonl"
            train_manifest.write_text("\n".join(json.dumps(x) for x in training), encoding="utf-8")
            external_manifest = root / "external.jsonl"
            external_manifest.write_text("\n".join(json.dumps(x) for x in external), encoding="utf-8")
            candidate = root / "candidate.json"; approved = root / "approved.json"
            completed = subprocess.run([
                sys.executable, "-m", "tools.run_evidence_candidate_pipeline",
                str(train_manifest), str(external_manifest), str(candidate), str(approved),
                "--model-id", "pipeline-test", "--text-bins", "64", "--external-min-rows", "4",
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
            self.assertTrue(candidate.is_file())
            self.assertFalse(approved.exists())
            status = json.loads(candidate.with_suffix(".pipeline.json").read_text(encoding="utf-8"))
            self.assertFalse(status["approved"])
            self.assertFalse(status["production_config_changed"])


if __name__ == "__main__":
    unittest.main()
