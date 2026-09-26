import unittest
from email.message import EmailMessage

from email_analyzer.reference_evidence import analyze_references, registrable_domain


class ReferenceTests(unittest.TestCase):
    def message(self, sender='notice@mail.notion.so', html=None):
        msg=EmailMessage();msg['From']=sender
        msg.set_content(html or '<a href="https://www.notion.so/page">open</a>',subtype='html')
        return msg

    def test_registrable_domain_handles_subdomains(self):
        self.assertEqual(registrable_domain('mail.notion.so'),'notion.so')

    def test_same_sender_site_is_observed(self):
        result=analyze_references(self.message())
        self.assertEqual(result['status'],'dynamic')
        self.assertEqual(result['domain_relationships'][0]['relationship'],'same_sender_domain')

    def test_external_site_is_observed_without_registry_judgment(self):
        result=analyze_references(self.message(html='<a href="https://other.example/login">open</a>'))
        self.assertEqual(result['domain_relationships'][0]['relationship'],'external_domain')
        self.assertEqual(result['official_claim_mismatch_count'],0)

    def test_reply_to_difference_is_observed(self):
        msg=self.message();msg['Reply-To']='reply@other.example'
        self.assertEqual(analyze_references(msg)['from_reply_relation'],'different_hosts')

    def test_static_registry_api_is_removed(self):
        import email_analyzer.reference_evidence as module
        self.assertFalse(hasattr(module,'load_registry'))


if __name__ == '__main__':unittest.main()
