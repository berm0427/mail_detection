import unittest
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email_analyzer.legacy_rules import annotate_auth_evidence, score_rules
from email_analyzer.engine_view import engine_rows, inconclusive_explanation

class AuthDisplayTests(unittest.TestCase):
    def test_actual_forged_fixture_unknown_parser(self):
        p=Path(__file__).parent/'synthetic_eml/user_acceptance_forged_pass.eml'
        msg=BytesParser(policy=policy.default).parsebytes(p.read_bytes())
        h=annotate_auth_evidence(dict.fromkeys(['spf_check','dkim_check','dmarc_check'],'unknown'), msg)
        for key in ['spf_check','dkim_check','dmarc_check']:
            self.assertEqual(h[key], 'unverified_pass')
            self.assertEqual(h['auth_evidence']['header_assertions'][key], ['pass'])
        rules=score_rules(h, {'total_matches':0,'categories':{}}, {}, {})
        self.assertEqual(rules['verdict'], 'inconclusive')
        text=engine_rows({'rule_result':rules})[0][3]
        self.assertIn('SPF 원문 Authentication-Results 관측: pass', text)
        self.assertIn('발행 출처 확인 자료 없음', text)
        explanation=inconclusive_explanation({'rule_result':rules, 'decision':{'unavailable_engines':[]}})
        self.assertIn('인증 근거', explanation)
        self.assertNotIn('일부 엔진', explanation)
    def test_absent_and_conflicting_headers(self):
        h=annotate_auth_evidence({},EmailMessage())
        self.assertEqual(h['auth_evidence']['header_assertions']['spf_check'], [])
        msg=EmailMessage();msg['Authentication-Results']='mx; spf=pass; spf=fail; dkim=pass'
        h=annotate_auth_evidence({},msg)
        self.assertEqual(h['spf_check'],'observed')
        self.assertEqual(h['dkim_check'],'unverified_pass')
    def test_comment_and_property_are_not_method_assertions(self):
        msg=EmailMessage();msg['Authentication-Results']='mx (spf=pass); reason="dkim=pass"; smtp.spf=pass; dmarc=pass'
        h=annotate_auth_evidence({},msg)
        self.assertEqual(h['auth_evidence']['header_assertions']['spf_check'],[])
        self.assertEqual(h['auth_evidence']['header_assertions']['dkim_check'],[])
    def test_local_verification_and_error_preserved(self):
        msg=EmailMessage();msg['Authentication-Results']='mx; spf=pass; dkim=pass'
        h=annotate_auth_evidence({'spf_check':'fail','dkim_check':'timeout','auth_evidence':{'source':{'spf_check':'local_verification'}}},msg)
        self.assertEqual(h['spf_check'],'fail')
        self.assertEqual(h['dkim_check'],'timeout')
    def test_engine_missing_explanation(self):
        text=inconclusive_explanation({'decision':{'unavailable_engines':['razor']}})
        self.assertIn('일부 엔진',text)
        self.assertNotIn('인증 근거',text)
