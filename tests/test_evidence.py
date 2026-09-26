import random,unittest
from email.message import EmailMessage
from email_analyzer.features.extractor import EmailFeatureExtractor
from email_analyzer.engine_view import engine_rows
from email_analyzer.body_analyzer import PhishingURLDetector
from email_analyzer.legacy_rules import annotate_auth_evidence, score_rules


class EvidenceTests(unittest.TestCase):
    def test_long_tracking_url_is_observed_but_not_scored_by_length_alone(self):
        detector = PhishingURLDetector()
        url = 'https://mg.mail.notion.so/c/' + ('a' * 180)
        self.assertTrue(detector.detect_phishing_features(url)['long_url'])
        self.assertEqual(detector.calculate_risk_score(url), 0)

    def test_url_rule_display_groups_same_host_source_and_score(self):
        result = {
            'risk_score': 0,
            'url_analysis': {
                'total_urls': 3,
                'analyzed_urls': [
                    {'url': 'https://mg.mail.notion.so/a', 'sources': ['html_href'], 'risk_score': 5},
                    {'url': 'https://mg.mail.notion.so/b', 'sources': ['html_href'], 'risk_score': 5},
                    {'url': 'https://notion.so', 'sources': ['body_text'], 'risk_score': 0},
                ],
            },
        }
        row = next(item for item in engine_rows(result) if item[0] == 'URL 규칙 검사')
        self.assertEqual(row[2], '주소 3개 · 표시 그룹 2개')
        self.assertEqual(row[3].count('mg.mail.notion.so'), 1)
        self.assertIn('mg.mail.notion.so · html_href · 규칙 점수 5 · URL 2개', row[3])

    def test_mime_attachment_and_auth_observations(self):
        msg=EmailMessage();msg['From']='sender@example.org';msg['To']='user@example.net'
        msg['Reply-To']='reply@example.net'
        msg['Authentication-Results']='test; spf=fail; dkim=fail; dmarc=fail'
        msg.set_content('Meeting notes.');msg.add_alternative('<a href="https://example.org">notes</a>',subtype='html')
        msg.add_attachment(b'inert test bytes',maintype='application',subtype='octet-stream',filename='sample.exe')
        values=EmailFeatureExtractor().extract(msg)
        self.assertEqual(values['authentication_fail_count'],3)
        self.assertEqual(values['attachment_bytes'],16)
        self.assertEqual(values['executable_attachment_count'],1)
        self.assertEqual(values['reply_to_domain_mismatch'],1)
        self.assertEqual(values['plain_part_count'],1)
        self.assertEqual(values['html_part_count'],1)
        self.assertEqual(values['url_count'],1)

    def test_failed_and_missing_results_are_not_safe(self):
        for status in ['error','skipped','missing']:
            rows=engine_rows({'verdict':'error','engine_results':{'razor':{'status':status}}})
            self.assertEqual(rows[0][1],'판정 불가')
            self.assertEqual(len(rows),1)

    def test_razor_miss_is_not_safety(self):
        rows=engine_rows({'engine_results':{'razor':{'status':'ok','details':{'catalogue_match':False}}}})
        self.assertEqual(len(rows),1)

    def test_only_razor_match_is_shown(self):
        rows=engine_rows({'engine_results':{'razor':{'status':'ok','details':{'catalogue_match':True}}}})
        self.assertEqual(rows[1][0],'Razor 스팸 서명')
        self.assertIn('최종 판정에 반영됨',rows[1][3])

    def test_rule_boundaries(self):
        body={'total_matches':0,'categories':{}}
        missing=score_rules({},body,{}, {})
        self.assertEqual(missing['risk_score'],0)
        self.assertEqual(missing['verdict'],'inconclusive')
        header={'spf_check':'pass','dkim_check':'pass','dmarc_check':'pass'}
        self.assertEqual(score_rules(header,body,{}, {})['verdict'],'legitimate')
        self.assertEqual(score_rules({},body,{'risk_score':100},{'typosquatting_detected':True})['verdict'],'suspicious')
        explicit_fail={'spf_check':'fail','dkim_check':'fail','dmarc_check':'fail'}
        self.assertEqual(score_rules(explicit_fail,body,{'risk_score':100},{'typosquatting_detected':True})['verdict'],'suspicious')

    def test_official_link_claim_mismatch_is_a_rule_signal(self):
        body={'total_matches':0,'categories':{}}
        clean=score_rules({},body,{}, {}, {'official_claim_mismatch_count':0})
        mismatch=score_rules({},body,{}, {}, {'official_claim_mismatch_count':1})
        self.assertEqual(clean['risk_score'],0)
        self.assertEqual(mismatch['risk_score'],30)
        self.assertEqual(mismatch['verdict'],'suspicious')
        self.assertIn('공식 기관 링크 주장과 목적지 도메인 불일치', mismatch['reasons'][0])

    def test_auth_missing_fail_pass_and_errors_are_distinct(self):
        body={'total_matches':0,'categories':{}}
        missing=score_rules({'spf_check':'missing','dkim_check':'unknown','dmarc_check':'none'},body,{}, {})
        self.assertEqual(missing['risk_score'],0)
        self.assertEqual(missing['verdict'],'inconclusive')
        self.assertTrue(missing['auth_summary']['incomplete'])
        fail=score_rules({'spf_check':'fail','dkim_check':'mismatch','dmarc_check':'fail'},body,{}, {})
        self.assertEqual(fail['risk_score'],35)
        self.assertEqual(fail['verdict'],'suspicious')
        self.assertEqual(len(fail['auth_summary']['failures']),3)
        soft=score_rules({'spf_check':'softfail','dkim_check':'neutral','dmarc_check':'permerror'},body,{}, {})
        self.assertEqual(soft['risk_score'],0)
        self.assertEqual(soft['verdict'],'inconclusive')
        self.assertEqual(len(soft['auth_summary']['errors']),1)
        pass_result=score_rules({'spf_check':'pass','dkim_check':'pass','dmarc_check':'pass'},body,{}, {})
        self.assertEqual(pass_result['verdict'],'legitimate')

    def test_missing_auth_with_other_risk_keeps_risk_not_auth_points(self):
        body={'total_matches':1,'categories':{'malicious':{'count':1}}}
        result=score_rules({},body,{'risk_score':0},{})
        self.assertEqual(result['risk_score'],0)
        self.assertEqual(result['verdict'],'inconclusive')
        result=score_rules({},body,{'risk_score':30},{})
        self.assertEqual(result['risk_score'],30)
        self.assertEqual(result['verdict'],'suspicious')

    def test_sender_insertable_authentication_results_is_not_verified_pass(self):
        body={'total_matches':0,'categories':{}}
        msg=EmailMessage();msg['Authentication-Results']='mx.example; spf=pass dkim=pass dmarc=pass'
        annotated=annotate_auth_evidence({'spf_check':'pass','dkim_check':'pass','dmarc_check':'pass'}, msg)
        self.assertEqual(annotated['spf_check'],'unverified_pass')
        self.assertEqual(annotated['auth_evidence']['source']['spf_check'],'raw_message_header')
        result=score_rules(annotated,body,{}, {})
        self.assertEqual(result['risk_score'],0)
        self.assertEqual(result['verdict'],'inconclusive')
        self.assertIn('auth_evidence', result)

    def test_sender_insertable_fail_is_risk_but_marked_raw_observation(self):
        body={'total_matches':0,'categories':{}}
        msg=EmailMessage();msg['Authentication-Results']='mx.example; spf=fail dkim=fail dmarc=fail'
        annotated=annotate_auth_evidence({'spf_check':'fail','dkim_check':'fail','dmarc_check':'fail'}, msg)
        self.assertEqual(annotated['spf_check'],'unverified_fail')
        self.assertEqual(annotated['auth_evidence']['source']['dkim_check'],'raw_message_header')
        result=score_rules(annotated,body,{}, {})
        self.assertEqual(result['risk_score'],35)
        self.assertEqual(result['verdict'],'suspicious')

    def test_engine_rows_show_auth_limitations(self):
        body={'total_matches':0,'categories':{}}
        result=score_rules({'spf_check':'missing','dkim_check':'fail','dmarc_check':'temperror'},body,{}, {})
        rows=engine_rows({'rule_result':result})
        self.assertIn('DKIM 명시적 실패', rows[0][3])
        self.assertIn('SPF 판정 제외 · 검증 자료 없음', rows[0][3])
        self.assertIn('DMARC 조회 오류', rows[0][3])

    def test_engine_rows_put_unified_decision_before_diagnostic_score(self):
        result={'risk_score':0,'risk_threshold':70,'decision':{
            'verdict':'suspicious','signals':[{
                'source':'official_site_discovery','summary':'유사 사칭 도메인 탐지',
                'reflected':True}]}}
        rows=engine_rows(result)
        self.assertEqual(rows[0][0],'통합 판정')
        self.assertIn('반영 신호 1건',rows[0][2])
        self.assertEqual(rows[1][0],'기존 규칙')
        self.assertIn('최종 판정과 별도',rows[1][3])


if __name__=='__main__':unittest.main()
