import unittest
from email.message import EmailMessage
from unittest.mock import Mock, patch

from email_analyzer.email_auth_verifier import verify_email_authentication


def message_bytes(from_address='sender@example.org', dkim_domain='example.org'):
    message = EmailMessage()
    message['From'] = from_address
    message['Return-Path'] = '<bounce@example.org>'
    message['Received'] = 'from mail.example.org ([93.184.216.34]) by mx.receiver.test with ESMTP'
    message['DKIM-Signature'] = f'v=1; d={dkim_domain}; s=selector; b=fake'
    message.set_content('test')
    return message.as_bytes()


class EmailAuthVerifierTests(unittest.TestCase):
    @patch('email_analyzer.email_auth_verifier._dmarc_policy')
    @patch('email_analyzer.email_auth_verifier.dkim.DKIM')
    def test_disabled_network_performs_no_dns_authentication(self, dkim_class, policy):
        result = verify_email_authentication(message_bytes(), allow_dns=False)
        dkim_class.return_value.verify.assert_not_called()
        policy.assert_not_called()
        self.assertEqual(result['dkim']['status'], 'not_evaluated')
        self.assertEqual(result['dmarc']['status'], 'not_evaluated')
        self.assertEqual(result['spf']['status'], 'not_evaluated')

    @patch('email_analyzer.email_auth_verifier.spf.check2', return_value=('pass', 'authorized'))
    @patch('email_analyzer.email_auth_verifier._dmarc_policy')
    @patch('email_analyzer.email_auth_verifier.dkim.DKIM')
    def test_verified_dkim_and_alignment_produce_dmarc_pass(self, dkim_class, policy, spf_check):
        dkim_class.return_value.verify.return_value = True
        policy.return_value = {'status': 'found', 'tags': {'p': 'reject', 'adkim': 'r'}}
        result = verify_email_authentication(message_bytes())
        self.assertEqual(result['dkim']['status'], 'pass')
        self.assertEqual(result['dmarc']['status_result'], 'pass')
        self.assertEqual(result['spf']['status'], 'pass')
        self.assertEqual(result['spf']['input_trust'], 'untrusted_stored_received_header')

    @patch('email_analyzer.email_auth_verifier.spf.check2', return_value=('fail', 'not authorized'))
    @patch('email_analyzer.email_auth_verifier._dmarc_policy')
    @patch('email_analyzer.email_auth_verifier.dkim.DKIM')
    def test_failed_signature_or_unaligned_domain_cannot_pass_dmarc(self, dkim_class, policy, spf_check):
        policy.return_value = {'status': 'found', 'tags': {'p': 'reject', 'adkim': 's'}}
        dkim_class.return_value.verify.return_value = False
        failed = verify_email_authentication(message_bytes())
        self.assertEqual(failed['dkim']['status'], 'fail')
        self.assertEqual(failed['dmarc']['status_result'], 'not_evaluated')
        dkim_class.return_value.verify.return_value = True
        unaligned = verify_email_authentication(message_bytes(dkim_domain='attacker.example'))
        self.assertEqual(unaligned['dkim']['status'], 'pass')
        self.assertFalse(unaligned['dmarc']['dkim_aligned'])
        self.assertEqual(unaligned['dmarc']['status_result'], 'not_evaluated')


if __name__ == '__main__':
    unittest.main()
