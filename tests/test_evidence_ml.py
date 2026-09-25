import json,tempfile,unittest
from email.message import EmailMessage
from pathlib import Path
from email_analyzer.evidence_features import EvidenceFeatureExtractor,hashed_char_ngrams,message_text
from email_analyzer.engines.evidence_ml import EvidenceMLEngine
from email_analyzer.decision import combine_evidence


class EvidenceMLTests(unittest.TestCase):
    def test_objective_features_include_link_html_and_scan(self):
        result={
          'url_analysis':{'total_urls':2,'risk_score':20,'analyzed_urls':[{'url':'http://bad.example','risk_score':20}]},
          'link_evidence':{'different_host_count':1},
          'reference_evidence':{'official_claim_mismatch_count':1,'from_reply_relation':'different_hosts','domain_relationships':[{'relationship':'unregistered'}]},
          'page_analysis':{'omitted':1,'pages':[{'status':'ok','structure':{'password_fields':1,'script_count':2,'iframe_count':1,'forms':[{'external_host':True,'insecure_http':True}]}},{'status':'error'}]},
          'rule_result':{'auth_summary':{'failures':[{}],'limitations':[{}],'errors':[]}},
          'body':{'categories':{'x':{'count':3,'scoring_count':2}},'action_signals':[{'kind':'urgent_payment_request'}]},
          'attachments':[{'size':1048576,'malware_scan':{'status':'threat_detected'}}],
          'engine_results':{'numerical_features':{'details':{'features':{'executable_attachment_count':1}}}},
        }
        f=EvidenceFeatureExtractor().extract(result)
        self.assertEqual(f['official_claim_mismatch'],1);self.assertEqual(f['page_external_forms'],1)
        self.assertEqual(f['attachment_threats'],1);self.assertEqual(f['attachment_megabytes'],1)
    def test_hashing_is_stable_and_attachments_are_excluded(self):
        m=EmailMessage();m['Subject']='안내';m.set_content('본문입니다')
        m.add_attachment(b'secret attachment words',maintype='text',subtype='plain',filename='x.txt')
        text=message_text(m);self.assertNotIn('secret attachment words',text)
        self.assertEqual(hashed_char_ngrams(text),hashed_char_ngrams(text))
    def test_only_gated_model_can_signal(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'model.json';extractor=EvidenceFeatureExtractor();n=len(extractor.FEATURE_NAMES);bins=32
            base={'model_id':'test','schema_version':1,'feature_names':list(extractor.FEATURE_NAMES),'text_bins':bins,
                  'positive_class':'label_1','decision_threshold':.5,'mean':[0]*n,'scale':[1]*n,'evidence_coef':[0]*n,'text_coef':[0]*bins,'intercept':10}
            message=EmailMessage();message.set_content('hello')
            for passed,expected in ((True,True),(False,False)):
                path.write_text(json.dumps({**base,'validation_gate':{'passed':passed}}),encoding='utf-8')
                engine=EvidenceMLEngine(path).analyze(message,{})
                result={'verdict':'inconclusive','risk_score':0,'rule_result':{'risk_score':0,'auth_summary':{'incomplete':True}},
                        'engine_results':{'numerical_features':{'status':'ok'},'ml_baseline':{'status':'ok','score':.1},'razor':{'status':'ok','details':{'catalogue_match':False}},'evidence_ml':engine.__dict__}}
                self.assertEqual(combine_evidence(result)['evidence_ml_signal'],expected)
    def test_attachment_detection_overrides_other_evidence(self):
        result={'verdict':'inconclusive','risk_score':0,'rule_result':{'risk_score':0,'auth_summary':{'incomplete':True}},
                'engine_results':{'numerical_features':{'status':'ok'},'ml_baseline':{'status':'ok','score':.1},'razor':{'status':'ok','details':{'catalogue_match':False}}},
                'attachments':[{'malware_scan':{'status':'threat_detected'}}]}
        decision=combine_evidence(result);self.assertEqual(decision['verdict'],'dangerous');self.assertEqual(decision['attachment_scan']['threats'],1)
