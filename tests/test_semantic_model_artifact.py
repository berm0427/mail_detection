import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SemanticModelArtifactTests(unittest.TestCase):
    def test_configured_model_matches_current_training_manifest(self):
        config = json.loads((ROOT / 'engine_config.json').read_text(encoding='utf-8'))
        artifact = json.loads((ROOT / config['semantic_ml_model']).read_text(encoding='utf-8'))
        manifest = ROOT / 'mail_body' / 'training_data' / 'korean_synthetic_v1' / 'training_manifest.jsonl'
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.assertEqual(artifact['manifest_sha256'], digest)
        self.assertEqual(artifact['training_rows'], 8000)
        self.assertEqual(artifact['selection'], 'validation_split')

    def test_configured_model_keeps_honest_test_metrics(self):
        config = json.loads((ROOT / 'engine_config.json').read_text(encoding='utf-8'))
        model_path = ROOT / config['semantic_ml_model']
        metrics = json.loads(model_path.with_suffix('.metrics.json').read_text(encoding='utf-8'))
        self.assertEqual(metrics['test']['n'], 1000)
        self.assertGreaterEqual(metrics['test']['recall'], .95)
        self.assertLessEqual(metrics['test']['fpr'], .05)


if __name__ == '__main__':
    unittest.main()
