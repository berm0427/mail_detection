"""Optional semantic dependencies must not disable portable local engines."""
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
PRELUDE = """
import importlib.abc
import sys
from email.message import EmailMessage

attempts = []
class UnavailableSemanticDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'numpy', 'sentence_transformers'}:
            attempts.append(fullname)
            raise ModuleNotFoundError('Dependency intentionally unavailable', name=fullname)
sys.meta_path.insert(0, UnavailableSemanticDependencies())

from email_analyzer.pipeline import (
    analyze_engines, analyze_evidence_engine, analyze_semantic_engine,
)
message = EmailMessage()
message.set_content('Synthetic offline regression message')
"""


class PipelineOptionalDependencyTests(unittest.TestCase):
    def run_isolated(self, source):
        # A fresh -S process also avoids already-loaded dependencies hiding bugs.
        completed = subprocess.run(
            [sys.executable, '-B', '-S', '-c', PRELUDE + textwrap.dedent(source)],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', EMAIL_DISABLE_REMOTE_AI='1'),
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_import_does_not_load_semantic_dependencies(self):
        self.run_isolated("assert attempts == [], attempts")

    def test_base_engines_work_without_semantic_dependencies(self):
        self.run_isolated("""
            results = analyze_engines(message, {'razor_command': []})
            assert set(results) == {'razor'}, results
            assert results['razor']['status'] == 'skipped', results
            assert attempts == [], attempts
        """)

    def test_evidence_engine_works_without_semantic_dependencies(self):
        self.run_isolated("""
            import json
            import tempfile
            from pathlib import Path
            from email_analyzer.evidence_features import EvidenceFeatureExtractor
            names = list(EvidenceFeatureExtractor.FEATURE_NAMES)
            with tempfile.TemporaryDirectory() as folder:
                model = Path(folder) / 'evidence.json'
                model.write_text(json.dumps({
                    'model_id': 'offline-fixture',
                    'schema_version': EvidenceFeatureExtractor.SCHEMA_VERSION,
                    'feature_names': names, 'positive_class': 'label_1',
                    'mean': [0] * len(names), 'scale': [1] * len(names),
                    'evidence_coef': [0] * len(names), 'intercept': 0,
                    'text_bins': 0, 'text_coef': [],
                }), encoding='utf-8')
                result = analyze_evidence_engine(message, {}, {'evidence_ml_model': str(model)})
            assert result['status'] == 'ok', result
            assert result['score'] == 0.5, result
            assert attempts == [], attempts
        """)

    def test_unconfigured_semantic_model_skips_without_import(self):
        self.run_isolated("""
            result = analyze_semantic_engine(message, {'semantic_ml_model': None})
            assert result['status'] == 'skipped', result
            assert result['score'] is None, result
            assert attempts == [], attempts
        """)

    def test_missing_semantic_model_skips_without_import(self):
        self.run_isolated("""
            import tempfile
            from pathlib import Path
            with tempfile.TemporaryDirectory() as folder:
                result = analyze_semantic_engine(message, {
                    'semantic_ml_model': str(Path(folder) / 'absent.json'),
                })
            assert result['status'] == 'skipped', result
            assert result['score'] is None, result
            assert attempts == [], attempts
        """)

    def test_missing_numpy_is_an_engine_error_not_a_pipeline_crash(self):
        self.run_isolated("""
            import json
            import tempfile
            from pathlib import Path
            with tempfile.TemporaryDirectory() as folder:
                model = Path(folder) / 'semantic.json'
                model.write_text(json.dumps({
                    'model_id': 'offline-fixture', 'embedding_model_path': 'unused',
                    'mean': [0], 'scale': [1], 'coef': [1], 'intercept': 0,
                }), encoding='utf-8')
                result = analyze_semantic_engine(message, {'semantic_ml_model': str(model)})
            assert result['status'] == 'error', result
            assert result['score'] is None, result
            assert result['error'].startswith('본문 문맥 ML 실행 실패: ModuleNotFoundError:'), result
            assert attempts == ['numpy'], attempts
            # No encoder download or successful/safe score is substituted.
            results = analyze_engines(message, {'razor_command': []})
            assert set(results) == {'razor'}, results
        """)


if __name__ == '__main__':
    unittest.main()
