import unittest

from email_analyzer.html_pair_features import pair_features
from email_analyzer.page_structure import inspect_structure


class HtmlPairFeatureTests(unittest.TestCase):
    def test_identical_structures_have_full_similarity(self):
        html = '<html><body><a href="/a">A</a><form><input name="q"></form></body></html>'
        left = inspect_structure(html, 'https://official.example/')
        right = inspect_structure(html, 'https://official.example/')
        features = pair_features(left, right, 'https://official.example/path')
        self.assertEqual(features['tag_histogram_similarity'], 1.0)
        self.assertEqual(features['structure_similarity'], 1.0)
        self.assertEqual(features['target_url_scheme_is_https'], 1.0)
        self.assertEqual(features['target_url_hostname_label_count'], 2.0)

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

    def test_url_structure_is_part_of_html_pair_schema(self):
        features = pair_features({}, {}, 'http://127.0.0.1:8081/a-b?next=https://x.example')
        self.assertEqual(features['target_url_host_is_ip'], 1.0)
        self.assertEqual(features['target_url_has_explicit_port'], 1.0)
        self.assertEqual(features['target_url_embedded_redirect_target_count'], 1.0)
        self.assertEqual(features['target_url_scheme_is_https'], 0.0)


if __name__ == '__main__':
    unittest.main()
