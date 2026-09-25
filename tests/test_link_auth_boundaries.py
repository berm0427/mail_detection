import unittest
from email.message import EmailMessage
from email_analyzer.link_evidence import inspect_html_links, same_hostname
from email_analyzer.legacy_rules import annotate_auth_evidence
from email_analyzer.engine_view import engine_rows


class BoundaryTests(unittest.TestCase):
    def message(self, html):
        m = EmailMessage(); m.set_content(html, subtype='html'); return m

    def test_visible_link_mismatch_and_nested_label(self):
        r = inspect_html_links(self.message('<a href="https://evil.example/login"><b>https://bank.example</b></a>'))
        self.assertEqual(r['different_host_count'], 1)
        self.assertEqual(r['links'][0]['target_host'], 'evil.example')

    def test_userinfo_is_not_destination(self):
        r = inspect_html_links(self.message('<a href="https://bank.example@evil.example">https://bank.example</a>'))
        self.assertEqual(r['different_host_count'], 1)

    def test_relative_without_base_is_unresolved(self):
        r = inspect_html_links(self.message('<a href="/login">https://bank.example</a>'))
        self.assertEqual(r['links'][0]['status'], 'unresolved')

    def test_base_is_message_observation(self):
        r = inspect_html_links(self.message('<base href="https://evil.example/"><a href="/login">https://bank.example</a>'))
        self.assertTrue(r['links'][0]['base_from_message'])
        self.assertEqual(r['different_host_count'], 1)

    def test_attachment_and_non_url_label(self):
        m = self.message('<a href="https://evil.example">로그인</a>')
        m.add_attachment(b'<a href="https://evil.example">https://bank.example</a>', maintype='text', subtype='html', filename='example.html')
        self.assertEqual(inspect_html_links(m)['links'], [])

    def test_domains_not_similarity_or_suffix(self):
        self.assertTrue(same_hostname('HTTPS://BANK.EXAMPLE./a', 'bank.example'))
        self.assertFalse(same_hostname('bank.example.evil.example', 'bank.example'))
        self.assertFalse(same_hostname('secure-bank-service.example', 'secure-bank-services.example'))
        self.assertFalse(same_hostname('', ''))
        self.assertTrue(same_hostname('bücher.example', 'xn--bcher-kva.example'))

    def test_pass_requires_recorded_local_source(self):
        h = annotate_auth_evidence({'spf_check': 'pass'}, EmailMessage())
        self.assertEqual(h['spf_check'], 'unverified_pass')
        self.assertNotEqual(h['auth_evidence']['source']['spf_check'], 'local_verification')
        h = annotate_auth_evidence({'spf_check': 'pass', 'auth_evidence': {'source': {'spf_check': 'local_verification'}}}, EmailMessage())
        self.assertEqual(h['spf_check'], 'pass')

    def test_forged_headers_cannot_override_local_failure(self):
        m = EmailMessage(); m['Authentication-Results'] = 'mx; spf=pass; dkim=pass'
        h = annotate_auth_evidence({'spf_check': 'fail', 'auth_evidence': {'source': {'spf_check': 'local_verification'}}}, m)
        self.assertEqual(h['spf_check'], 'fail')
        self.assertEqual(h['dkim_check'], 'unverified_pass')

    def test_engine_view_shows_evidence_without_score_change(self):
        r = {'risk_score': 0, 'link_evidence': inspect_html_links(self.message('<a href="https://evil.example">https://bank.example</a>'))}
        self.assertTrue(any(x[0] == 'HTML 링크 비교' and '1건' in x[2] for x in engine_rows(r)))
        self.assertEqual(r['risk_score'], 0)
