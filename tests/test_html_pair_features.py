import unittest

from email_analyzer.html_pair_features import pair_features
from email_analyzer.page_structure import inspect_structure


class HtmlPairFeatureTests(unittest.TestCase):
    def test_identical_structures_have_full_similarity(self):
        html = '<html><body><a href="/a">A</a><form><input name="q"></form></body></html>'
        left = inspect_structure(html, 'https://official.example/')
        right = inspect_structure(html, 'https://official.example/')
        features = pair_features(left, right)
        self.assertEqual(features['tag_histogram_similarity'], 1.0)
        self.assertEqual(features['structure_similarity'], 1.0)

    def test_phishing_form_difference_is_preserved(self):
        official = inspect_structure('<html><body><p>안내</p></body></html>', 'https://official.example/')
        target = inspect_structure(
            '<html><body><form action="http://collector.example/submit">'
            '<input type="password" name="pw"><button>확인</button></form></body></html>',
            'https://lookalike.example/',
        )
        features = pair_features(target, official)
        self.assertEqual(features['password_fields_delta'], 1.0)
        self.assertEqual(features['target_external_forms'], 1.0)
        self.assertEqual(features['target_insecure_forms'], 1.0)
        self.assertLess(features['structure_similarity'], 1.0)


if __name__ == '__main__':
    unittest.main()
