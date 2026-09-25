import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.collect_html_pair_dataset import load_side


class CollectHtmlPairDatasetTests(unittest.TestCase):
    def test_loads_archived_html_relative_to_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'page.html').write_text('<form><input type="password"></form>', encoding='utf-8')
            result, source = load_side({
                'target_html': 'page.html', 'target_source_url': 'https://captured.example/login'
            }, 'target', root)
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(result['structure']['password_fields'], 1)
            self.assertEqual(source['kind'], 'html')

    def test_fetches_live_url(self):
        fetched = {'status': 'ok', 'structure': {'element_count': 1}}
        with patch('tools.collect_html_pair_dataset.fetch_page', return_value=fetched) as fetch:
            result, source = load_side({'reference_url': 'https://official.example'}, 'reference', Path('.'))
        self.assertEqual(result, fetched)
        self.assertEqual(source, {'kind': 'url', 'value': 'https://official.example'})
        fetch.assert_called_once_with('https://official.example')

    def test_live_url_cache_avoids_duplicate_fetch(self):
        fetched = {'status': 'ok', 'structure': {'element_count': 1}}
        cache = {}
        with patch('tools.collect_html_pair_dataset.fetch_page', return_value=fetched) as fetch:
            load_side({'reference_url': 'https://official.example'}, 'reference', Path('.'), cache)
            load_side({'reference_url': 'https://official.example'}, 'reference', Path('.'), cache)
        fetch.assert_called_once()

    def test_requires_exactly_one_source(self):
        with self.assertRaises(ValueError):
            load_side({}, 'target', Path('.'))
        with self.assertRaises(ValueError):
            load_side({'target_url': 'https://a.example', 'target_html': 'a.html'}, 'target', Path('.'))


if __name__ == '__main__':
    unittest.main()
