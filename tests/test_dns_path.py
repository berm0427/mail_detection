import unittest
from unittest.mock import patch
from email.message import EmailMessage
import dns.resolver
from unittest.mock import Mock
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
    def test_dkim_signature_presence_is_not_cryptographic_pass(self):
        msg=EmailMessage();msg['From']='sender@example.org'
        msg['DKIM-Signature']='v=1; d=example.org; s=selector; b=not-a-real-signature'
        msg.set_content('test')
        self.a.analysis_result['sender_domain']='example.org'
        self.a.analyze_dkim_dmarc(msg)
        self.assertEqual(self.a.analysis_result['dkim_check'],'observed_signature')
        self.assertEqual(self.a.analysis_result['details']['dkim_signature_domain'],'example.org')
    def test_spf_observation_mismatch_does_not_exit_or_claim_verified_failure(self):
        self.a.analysis_result['from_domain']='corp.example'
        self.a.spf_ip_list=['192.0.2.1']
        self.a.dig_ip_list=['198.51.100.0/24']
        self.assertFalse(self.a.compare_ip_lists())
        self.assertEqual(self.a.analysis_result['spf_check'],'observed')
        self.assertEqual(self.a.analysis_result['details']['spf_ip_comparison'],
                         'observed_mismatch_not_spf_verification')
    def test_consumer_mail_domain_does_not_skip_spf_observation(self):
        self.a.analysis_result['from_domain']='kakao.com'
        self.a.spf_ip_list=['220.64.109.48']
        self.a.dig_ip_list=['220.64.109.0/24']
        self.assertTrue(self.a.compare_ip_lists())
        self.assertEqual(self.a.analysis_result['spf_check'],'observed')
    def test_spf_all_qualifiers_are_not_conflated(self):
        def answers(record):
            item=Mock();item.to_text.return_value=f'"v=spf1 {record}"';return [item]
        with patch.object(self.a,'_resolve_dns',return_value=answers('~all')):
            self.a.check_spf_record('soft.example')
        with patch.object(self.a,'_resolve_dns',return_value=answers('-all')):
            self.a.check_spf_record('hard.example')
        observations=self.a.analysis_result['details']['spf_policy_observations']
        self.assertEqual([item['policy'] for item in observations],['softfail','hardfail'])
