"""Training metrics must not overwrite any other pipeline artifact."""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import run_evidence_candidate_pipeline as pipeline


class CandidateMetricsPathTests(unittest.TestCase):
    def assert_rejected_without_writes(self, root, candidate, approved):
        before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
        entries = set(root.rglob('*'))
        argv = ['pipeline', str(root / 'train.jsonl'), str(root / 'external.jsonl'),
                str(candidate), str(approved), '--model-id', 'metrics-fixture']

        def failed_training(command):
            # train_evidence_ml writes metrics before checking its internal gate,
            # even when it never writes a candidate and exits with gate failure.
            candidate.with_suffix('.metrics.json').write_bytes(b'failed training metrics')
            return subprocess.CompletedProcess(command, 2)

        with patch.object(sys, 'argv', argv), \
                patch.object(pipeline, 'check_independence', return_value={'passed': True}) as check, \
                patch.object(pipeline, 'run', side_effect=failed_training) as run, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as caught:
                pipeline.main()
        self.assertEqual(before, {p: p.read_bytes() for p in root.rglob('*') if p.is_file()})
        self.assertEqual(entries, set(root.rglob('*')))
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('paths must differ', stderr.getvalue())
        self.assertNotIn(str(root), stderr.getvalue())
        check.assert_not_called()
        run.assert_not_called()

    def test_metrics_cannot_alias_approved_model(self):
        for alias in ('direct', 'symlink', 'parent_symlink', 'hardlink'):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate = root / 'candidate.json'
                metrics = candidate.with_suffix('.metrics.json')
                metrics.write_bytes(b'existing approved artifact')
                approved = root / 'approved.json'
                if alias == 'direct':
                    approved = metrics
                elif alias == 'parent_symlink':
                    directory = root / 'alias'
                    directory.symlink_to(root, target_is_directory=True)
                    approved = directory / metrics.name
                elif alias == 'symlink':
                    approved.symlink_to(metrics)
                else:
                    approved.hardlink_to(metrics)
                self.assert_rejected_without_writes(root, candidate, approved)

    def exercise_other_artifact(self, artifact):
        for alias in ('symlink', 'hardlink'):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate = root / 'candidate.json'
                target = {'candidate': candidate,
                          'report': candidate.with_suffix('.external.json'),
                          'status': candidate.with_suffix('.pipeline.json')}[artifact]
                target.write_bytes(b'existing artifact')
                metrics = candidate.with_suffix('.metrics.json')
                if alias == 'symlink':
                    metrics.symlink_to(target)
                else:
                    metrics.hardlink_to(target)
                self.assert_rejected_without_writes(root, candidate, root / 'approved.json')

    def test_metrics_cannot_alias_candidate(self):
        self.exercise_other_artifact('candidate')

    def test_metrics_cannot_alias_external_report(self):
        self.exercise_other_artifact('report')

    def test_metrics_cannot_alias_status(self):
        self.exercise_other_artifact('status')

    def test_nonexistent_metrics_collision_creates_no_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'new' / 'candidate.json'
            self.assert_rejected_without_writes(root, candidate,
                                                candidate.with_suffix('.metrics.json'))


if __name__ == '__main__':
    unittest.main()
