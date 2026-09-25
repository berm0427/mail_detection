"""Artifact aliases must be rejected before any pipeline writes or training."""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import run_evidence_candidate_pipeline as pipeline


class CandidateArtifactPathTests(unittest.TestCase):
    def exercise_collision(self, artifact, alias):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'candidate.json'
            report = candidate.with_suffix('.external.json')
            status = candidate.with_suffix('.pipeline.json')
            approved = root / 'approved.json'
            paths = {'candidate': candidate, 'report': report, 'status': status}
            for path in (*paths.values(), approved):
                path.write_bytes(b'existing artifact must survive')
            target = paths[artifact]
            if alias == 'direct':
                approved = target
            elif alias == 'parent_symlink':
                directory = root / 'alias'
                directory.symlink_to(root, target_is_directory=True)
                approved = directory / target.name
            else:
                approved = root / 'linked-approved.json'
                if alias == 'symlink':
                    approved.symlink_to(target)
                else:
                    approved.hardlink_to(target)
            before = {p: p.read_bytes() for p in root.iterdir() if p.is_file()}
            self.assert_early_rejection(root, candidate, approved)
            self.assertEqual(before, {p: p.read_bytes() for p in root.iterdir() if p.is_file()})

    def assert_early_rejection(self, root, candidate, approved):
        argv = ['pipeline', str(root / 'train.jsonl'), str(root / 'external.jsonl'),
                str(candidate), str(approved), '--model-id', 'path-fixture']

        def failed_training(command):
            # Reproduce the write a trainer may make even before a failed gate.
            candidate.write_bytes(b'unapproved candidate')
            return subprocess.CompletedProcess(command, 1)

        with patch.object(sys, 'argv', argv), \
                patch.object(pipeline, 'check_independence', return_value={'passed': True}) as check, \
                patch.object(pipeline, 'run', side_effect=failed_training) as run, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as caught:
                pipeline.main()
        # Check preservation before assertions about exit/status so regressions
        # identify real writes, not merely an error-message mismatch.
        if approved.exists():
            self.assertEqual(approved.read_bytes(), b'existing artifact must survive')
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('paths must differ', stderr.getvalue())
        self.assertNotIn(str(root), stderr.getvalue())
        check.assert_not_called()
        run.assert_not_called()

    def test_approved_direct_artifact_collisions(self):
        for artifact in ('candidate', 'report', 'status'):
            with self.subTest(artifact=artifact):
                self.exercise_collision(artifact, 'direct')

    def test_approved_symlink_artifact_collisions(self):
        for artifact in ('candidate', 'report', 'status'):
            with self.subTest(artifact=artifact):
                self.exercise_collision(artifact, 'symlink')

    def test_approved_hardlink_artifact_collisions(self):
        for artifact in ('candidate', 'report', 'status'):
            with self.subTest(artifact=artifact):
                self.exercise_collision(artifact, 'hardlink')

    def test_approved_parent_symlink_collisions(self):
        for artifact in ('candidate', 'report', 'status'):
            with self.subTest(artifact=artifact):
                self.exercise_collision(artifact, 'parent_symlink')

    def test_nonexistent_collisions_create_no_directory(self):
        for suffix in ('.external.json', '.pipeline.json'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate = root / 'new' / 'candidate.json'
                self.assert_early_rejection(root, candidate, candidate.with_suffix(suffix))
                self.assertEqual(list(root.iterdir()), [])

    def test_candidate_report_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'candidate.json'
            candidate.write_bytes(b'existing artifact must survive')
            candidate.with_suffix('.external.json').hardlink_to(candidate)
            self.assert_early_rejection(root, candidate, root / 'approved.json')
            self.assertEqual(candidate.read_bytes(), b'existing artifact must survive')

    def test_report_status_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'candidate.json'
            report = candidate.with_suffix('.external.json')
            report.write_bytes(b'existing artifact must survive')
            candidate.with_suffix('.pipeline.json').symlink_to(report)
            self.assert_early_rejection(root, candidate, root / 'approved.json')
            self.assertEqual(report.read_bytes(), b'existing artifact must survive')


if __name__ == '__main__':
    unittest.main()
