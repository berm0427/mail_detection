import unittest
from unittest.mock import patch
from email.message import EmailMessage
import dns.resolver
from mail_header.mail_header_detection_v4 import EmailHeaderAnalyzer

class DNSPathTests(unittest.TestCase):
    def setUp(self):
        self.a=EmailHeaderAnalyzer()
    def test_from_fallback_without_received(self):
        msg=EmailMessage();msg['From']='sender@corp.example';msg.set_content('test')
        self.assertEqual(self.a.analyze_header_chain(msg),'corp.example')
        self.assertIsNone(self.a.analysis_result['technical_sender_domain'])
    def test_reserved_domain_still_parses_auth(self):
        msg=EmailMessage();msg['From']='sender@bad.example';msg['Authentication-Results']='mx; dkim=pass; dmarc=pass';msg.set_content('test')
        with patch.object(self.a,'check_dns_records') as dns_call, patch.object(self.a,'check_whois_info') as whois_call, patch.object(self.a,'analyze_dkim_dmarc') as auth:
            result=self.a.analyze_email(msg.as_bytes())
        dns_call.assert_not_called();whois_call.assert_not_called();auth.assert_called_once()
        self.assertEqual(result['details']['dns_queries'][0]['status'],'reserved_test_domain')
    def test_dns_outcomes_distinct(self):
        for error,status in [(dns.resolver.NXDOMAIN(),'nxdomain'),(dns.resolver.NoAnswer(),'no_record'),(dns.exception.Timeout(),'timeout')]:
            with patch('dns.resolver.resolve',side_effect=error):
                with self.assertRaises(type(error)):self.a._resolve_dns('example.org','A')
            self.assertEqual(self.a.analysis_result['details']['dns_queries'][-1]['status'],status)
    def test_public_from_reaches_lookup(self):
        msg=EmailMessage();msg['From']='sender@iana.org';msg.set_content('test')
        with patch.object(self.a,'check_dns_records') as dns_call, patch.object(self.a,'check_whois_info'), patch.object(self.a,'analyze_dkim_dmarc'), patch.object(self.a,'compare_ip_lists'):
            self.a.analyze_email(msg.as_bytes())
        dns_call.assert_called_once_with('iana.org')
