import json
import tempfile
import unittest
from pathlib import Path

from email_analyzer.decision import combine_evidence
from email_analyzer.engines.html_pair_ml import HtmlPairMLEngine
from email_analyzer.html_pair_features import FEATURE_NAMES, SCHEMA_VERSION, pair_features


class HtmlPairMLTests(unittest.TestCase):
    def model(self, path, passed=True):
        size = len(FEATURE_NAMES)
        model = {'model_id':'pair-test','schema_version':SCHEMA_VERSION,
                 'feature_names':list(FEATURE_NAMES),'mean':[0]*size,'scale':[1]*size,
                 'coef':[0]*size,'intercept':10,'decision_threshold':0.5,
                 'validation_gate':{'passed':passed}}
        path.write_text(json.dumps(model),encoding='utf-8')

    def comparison(self):
        return {'comparisons':[{'target_host':'lookalike.example','reference_host':'official.example',
                                'features':pair_features({}, {})}]}

    def test_gated_model_scores_verified_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'model.json';self.model(path)
            result=HtmlPairMLEngine(path).analyze(self.comparison())
            self.assertEqual(result.status,'ok');self.assertEqual(result.details['predicted_label'],1)

    def test_failed_gate_cannot_score(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'model.json';self.model(path,False)
            self.assertEqual(HtmlPairMLEngine(path).analyze(self.comparison()).status,'error')

    def test_positive_pair_changes_decision(self):
        engine={'status':'ok','score':0.9,'error':None,'details':{'predicted_label':1,
                'validation_gate':{'passed':True},'highest_risk_pair':{'target_host':'bad','reference_host':'official'}}}
        result={'verdict':'inconclusive','risk_score':0,
                'rule_result':{'risk_score':0,'auth_summary':{'incomplete':True}},
                'engine_results':{'html_pair_ml':engine,'razor':{'status':'ok','details':{'catalogue_match':False}}}}
        decision=combine_evidence(result)
        self.assertEqual(decision['verdict'],'suspicious')
        self.assertTrue(decision['html_pair_ml_signal'])


if __name__=='__main__':unittest.main()
