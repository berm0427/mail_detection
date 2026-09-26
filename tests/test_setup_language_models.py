import tempfile
import unittest
from pathlib import Path

from tools.setup_language_models import model_ready


class LanguageModelSetupTests(unittest.TestCase):
    def test_model_ready_requires_every_marker_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'config.json').write_text('{}', encoding='utf-8')
            self.assertFalse(model_ready(root, ('config.json', 'vocab.json')))
            (root / 'vocab.json').write_text('{}', encoding='utf-8')
            self.assertTrue(model_ready(root, ('config.json', 'vocab.json')))


if __name__ == '__main__':
    unittest.main()
