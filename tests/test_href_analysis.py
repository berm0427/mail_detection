import unittest
from email.message import EmailMessage
from unittest.mock import Mock
from email_analyzer.link_evidence import collect_href_urls
from email_analyzer.body_analyzer import BodyAnalyzer

class HrefTests(unittest.TestCase):
    def test_body_text_does_not_emit_keyword_action_signals(self):
        result = BodyAnalyzer().analyze_text('지금 즉시 송금하세요')
        self.assertNotIn('action_signals', result)

    def msg(self, html):
        m=EmailMessage();m.set_content(html,subtype='html');return m
    def test_destination_and_dedup(self):
        m=self.msg('<a href="https://other.example/login?a=1&amp;b=2">https://bank.example/login</a>')
        links=collect_href_urls(m)
        self.assertEqual(links[0]['url'],'https://other.example/login?a=1&b=2')
        a=BodyAnalyzer.__new__(BodyAnalyzer)
        a.url_detector=Mock()
        a.url_detector.detect_phishing_features.return_value={}
        a.url_detector.calculate_risk_score.return_value=0
        r=a.analyze_urls('https://bank.example/login',links+links)
        self.assertEqual(r['total_urls'],2)
        self.assertEqual(a.url_detector.calculate_risk_score.call_count,2)
        self.assertEqual(r['analyzed_urls'][1]['sources'],['html_href'])
    def test_relative_nonweb_attachment(self):
        m=self.msg('<a href="/unresolved">x</a><a href="javascript:alert(1)">x</a><a href="//target.example/a">x</a>')
        m.add_attachment('<a href="https://attached.example">x</a>',subtype='html',filename='attached.html')
        self.assertEqual([x['url'] for x in collect_href_urls(m)],['https://target.example/a'])
    def test_base_and_shared_origins(self):
        links=collect_href_urls(self.msg('<base href="https://base.example/"><a href="login">x</a>'))
        self.assertTrue(links[0]['base_from_message'])
        a=BodyAnalyzer.__new__(BodyAnalyzer);a.url_detector=Mock()
        a.url_detector.detect_phishing_features.return_value={};a.url_detector.calculate_risk_score.return_value=0
        r=a.analyze_urls('https://base.example/login',links)
        self.assertEqual(r['total_urls'],1)
        self.assertEqual(r['analyzed_urls'][0]['sources'],['body_text','html_href'])
