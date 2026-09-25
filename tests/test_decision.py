import unittest
from email_analyzer.decision import combine_evidence


class DecisionTests(unittest.TestCase):
    def result(self,score=.2,match=False):
        return {'verdict':'legitimate','risk_score':0,'engine_results':{
            'numerical_features':{'status':'ok'},'ml_baseline':{'status':'ok','score':score},
            'razor':{'status':'ok','details':{'catalogue_match':match}}}}
    def test_ml_advisory_only(self):
        r=self.result(.99);d=combine_evidence(r)
        self.assertEqual(d['verdict'],'legitimate');self.assertFalse(d['review_required'])
        self.assertEqual(r['risk_score'],0)
    def test_razor_match_prompts_review_not_danger(self):
        self.assertEqual(combine_evidence(self.result(match=True))['verdict'],'suspicious')
    def test_missing_does_not_become_safe(self):
        r=self.result();r['engine_results']['razor']={'status':'error'}
        self.assertEqual(combine_evidence(r)['verdict'],'legitimate')
    def test_error_and_danger_not_downgraded(self):
        for verdict in ['error','dangerous']:
            self.assertEqual(combine_evidence({'verdict':verdict})['verdict'],verdict)
    def test_threshold(self):
        self.assertFalse(combine_evidence(self.result(.8999))['ml_review_signal'])
        self.assertFalse(combine_evidence(self.result(.9))['ml_review_signal'])
    def test_malformed_success_is_incomplete(self):
        for score in [float('nan'), float('inf'), -1, 2, None, True]:
            self.assertEqual(combine_evidence(self.result(score))['verdict'],'legitimate')
    def test_incomplete_auth_alone_is_not_a_risk_signal(self):
        r=self.result();r['rule_result']={'auth_summary':{'incomplete':True,'limitations':[{'method':'SPF','status':'missing'}]}}
        d=combine_evidence(r)
        self.assertEqual(d['verdict'],'legitimate')
        self.assertFalse(d['review_required'])
    def test_auth_failure_reason_is_preserved(self):
        r=self.result();r['verdict']='suspicious';r['rule_result']={'auth_summary':{'failures':[{'method':'SPF','status':'fail'}]}}
        d=combine_evidence(r)
        self.assertEqual(d['verdict'],'suspicious')
        self.assertTrue(any('명시적인 이메일 인증 실패' in reason for reason in d['reasons']))
    def test_inconclusive_requires_review_after_auth_upgrade(self):
        r=self.result();r['rule_result']={'auth_summary':{'incomplete':True}}
        d=combine_evidence(r)
        self.assertEqual(d['policy_version'],'evidence-review-v6')
        self.assertEqual(d['verdict'],'legitimate')
        self.assertFalse(d['review_required'])
    def test_razor_match_raises_inconclusive_to_suspicious_preserving_auth_reason(self):
        r=self.result(match=True);r['verdict']='inconclusive';r['rule_result']={'auth_summary':{'incomplete':True}}
        d=combine_evidence(r)
        self.assertEqual(d['verdict'],'suspicious')
        self.assertTrue(d['review_required'])
        self.assertTrue(d['razor_match'])
    def test_razor_match_does_not_downgrade_danger_or_error(self):
        for verdict in ['dangerous','error']:
            r=self.result(match=True);r['verdict']=verdict;r['rule_result']={'auth_summary':{'incomplete':True}}
            d=combine_evidence(r)
            self.assertEqual(d['verdict'],verdict)
            self.assertTrue(d['review_required'])
    def test_decision_matrix_meaningful_combinations(self):
        cases=[
            ('legitimate',False,False,'legitimate',False),
            ('legitimate',True,False,'legitimate',False),
            ('legitimate',False,True,'suspicious',True),
            ('legitimate',True,True,'suspicious',True),
            ('suspicious',True,False,'suspicious',True),
            ('dangerous',True,True,'dangerous',True),
            ('error',True,True,'error',True),
        ]
        for original,incomplete,razor,expected,review in cases:
            with self.subTest(original=original,incomplete=incomplete,razor=razor):
                r=self.result(match=razor);r['verdict']=original
                r['rule_result']={'auth_summary':{'incomplete':incomplete} if incomplete else {}}
                d=combine_evidence(r)
                self.assertEqual(d['verdict'],expected)
                self.assertEqual(d['review_required'],review)

    def test_semantic_ml_alone_is_advisory(self):
        r=self.result();r['engine_results']['semantic_ml']={
            'status':'ok','score':.98,'details':{'predicted_label':1}}
        d=combine_evidence(r)
        self.assertEqual(d['verdict'],'legitimate')
        self.assertTrue(d['semantic_ml_signal'])
        self.assertFalse(d['semantic_ml_corroborated'])
        self.assertTrue(d['semantic_ml_integrated'])

    def test_semantic_ml_with_objective_url_signal_is_used(self):
        r=self.result();r['engine_results']['semantic_ml']={
            'status':'ok','score':.98,'details':{'predicted_label':1}}
        r['url_analysis']={'analyzed_urls':[{'risk_score':25}]}
        d=combine_evidence(r)
        self.assertEqual(d['verdict'],'suspicious')
        self.assertTrue(d['semantic_ml_corroborated'])
        self.assertIn('url_rule',d['semantic_ml_objective_signals'])


if __name__=='__main__':unittest.main()
