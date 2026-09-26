import unittest
from unittest.mock import Mock, patch

from tools.build_korean_official_collection import discover, normalize, site_key


class KoreanOfficialCollectionTests(unittest.TestCase):
    def test_site_key_groups_subdomains_without_a_domain_allowlist(self):
        self.assertEqual(site_key('https://mail.example.co.kr/path'), 'example.co.kr')
        self.assertEqual(site_key('https://www.example.co.kr/'), 'example.co.kr')

    def test_normalize_removes_query_and_fragment(self):
        self.assertEqual(normalize('HTTPS://Example.COM/a?q=1#part'), 'https://example.com/a')

    @patch('tools.build_korean_official_collection.requests.get')
    def test_discover_keeps_only_same_site_html_links(self, get):
        response = Mock()
        response.url = 'https://www.example.co.kr/'
        response.headers = {'Content-Type': 'text/html; charset=utf-8'}
        response.content = (b'<a href="/notice?q=1">notice</a>'
                            b'<a href="https://evil.example/login">external</a>'
                            b'<a href="/manual.pdf">document</a>')
        response.raise_for_status.return_value = None
        get.return_value = response
        pages, error = discover('https://www.example.co.kr/', 5, 1)
        self.assertIsNone(error)
        self.assertEqual(pages, ['https://www.example.co.kr/',
                                 'https://www.example.co.kr/notice'])


if __name__ == '__main__':
    unittest.main()
