"""Pipeline outputs must preserve both input manifests, including aliases."""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import run_evidence_candidate_pipeline as pipeline


class CandidateManifestPathTests(unittest.TestCase):
    def exercise_alias(self, alias):
        for role in ('training', 'external'):
            for artifact in ('candidate', 'approved', 'metrics', 'report', 'status'):
                with self.subTest(role=role, artifact=artifact), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    candidate = root / 'candidate.json'
                    approved = root / 'approved.json'
                    outputs = {
                        'candidate': candidate, 'approved': approved,
                        'metrics': candidate.with_suffix('.metrics.json'),
                        'report': candidate.with_suffix('.external.json'),
                        'status': candidate.with_suffix('.pipeline.json'),
                    }
                    target = outputs[artifact]
                    target.write_bytes(b'input manifest must survive')
                    manifests = {name: root / f'{name}.jsonl' for name in ('training', 'external')}
                    other = 'external' if role == 'training' else 'training'
                    manifests[other].write_bytes(b'other input manifest')
                    if alias == 'direct':
                        manifests[role] = target
                    elif alias == 'parent_symlink':
                        directory = root / 'alias'
                        directory.symlink_to(root, target_is_directory=True)
                        manifests[role] = directory / target.name
                    elif alias == 'symlink':
                        manifests[role].symlink_to(target)
                    else:
                        manifests[role].hardlink_to(target)
                    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
                    entries = set(root.rglob('*'))

                    def run(command):
                        # Match the pipeline's writes without optional training
                        # packages or any real model/data. Success reaches copy2.
                        if 'email_analyzer.train_evidence_ml' in command:
                            outputs['metrics'].write_bytes(b'new metrics')
                            candidate.write_bytes(b'new candidate')
                        else:
                            outputs['report'].write_bytes(b'{"promotion_allowed": true}')
                        return subprocess.CompletedProcess(command, 0)

                    argv = ['pipeline', str(manifests['training']), str(manifests['external']),
                            str(candidate), str(approved), '--model-id', 'manifest-fixture']
                    code = 0
                    with patch.object(sys, 'argv', argv), \
                            patch.object(pipeline, 'check_independence', return_value={'passed': True}) as check, \
                            patch.object(pipeline, 'run', side_effect=run) as runner, \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()) as stderr:
                        try:
                            pipeline.main()
                        except SystemExit as exc:
                            code = exc.code
                    self.assertEqual(before, {p: p.read_bytes() for p in root.rglob('*') if p.is_file()})
                    self.assertEqual(entries, set(root.rglob('*')))
                    self.assertEqual(code, 2)
                    self.assertIn('input manifest', stderr.getvalue())
                    self.assertNotIn(str(root), stderr.getvalue())
                    check.assert_not_called()
                    runner.assert_not_called()

    def test_direct_manifest_output_collisions(self):
        self.exercise_alias('direct')

    def test_symlink_manifest_output_collisions(self):
        self.exercise_alias('symlink')

    def test_parent_symlink_manifest_output_collisions(self):
        self.exercise_alias('parent_symlink')

    def test_hardlink_manifest_output_collisions(self):
        self.exercise_alias('hardlink')

    def test_real_cli_preflight_failure_cannot_overwrite_manifest_with_status(self):
        for role in ('training', 'external'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate = root / 'candidate.json'
                manifest = candidate.with_suffix('.pipeline.json')
                original = b'not valid JSON: preserve for repair\n'
                manifest.write_bytes(original)
                inputs = [manifest, root / 'missing.jsonl']
                if role == 'external':
                    inputs.reverse()
                result = subprocess.run(
                    [sys.executable, '-B', '-S', '-m', 'tools.run_evidence_candidate_pipeline',
                     *map(str, inputs), str(candidate), str(root / 'approved.json'),
                     '--model-id', 'manifest-fixture'], capture_output=True, text=True, timeout=15)
                self.assertEqual(manifest.read_bytes(), original)
                self.assertEqual(result.returncode, 2)
                self.assertIn('input manifest', result.stderr)
                self.assertNotIn(str(root), result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(list(root.iterdir()), [manifest])

    def test_nonexistent_manifest_output_collision_creates_no_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'new' / 'candidate.json'
            result = subprocess.run(
                [sys.executable, '-B', '-S', '-m', 'tools.run_evidence_candidate_pipeline',
                 str(candidate), str(root / 'missing.jsonl'), str(candidate),
                 str(root / 'approved.json'), '--model-id', 'manifest-fixture'],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(result.returncode, 2)
            self.assertIn('input manifest', result.stderr)


if __name__ == '__main__':
    unittest.main()
