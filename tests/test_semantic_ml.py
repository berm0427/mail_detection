import json,tempfile,unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch
import numpy as np
from email_analyzer.engines.semantic_ml import SemanticMLEngine,_ENCODERS

class FakeEncoder:
    def encode(self,*args,**kwargs):return np.asarray([[1.0,0.0]])

class SemanticMLTests(unittest.TestCase):
    def test_advisory_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'model.json';model={'model_id':'semantic-test','embedding_model_path':'fake','mean':[0,0],'scale':[1,1],'coef':[1,0],'intercept':0,'decision_threshold':.5,'training_rows':10}
            path.write_text(json.dumps(model),encoding='utf-8');_ENCODERS['fake']=FakeEncoder()
            msg=EmailMessage();msg.set_content('hello');result=SemanticMLEngine(path).analyze(msg)
            self.assertEqual(result.status,'ok');self.assertGreater(result.score,.5)
            self.assertEqual(result.details['role'],'context_evidence')
            self.assertTrue(result.details['requires_objective_corroboration'])

    def test_foreign_text_uses_translated_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'model.json';model={'model_id':'semantic-test','embedding_model_path':'fake','mean':[0,0],'scale':[1,1],'coef':[1,0],'intercept':0,'decision_threshold':.5,'training_rows':10}
            path.write_text(json.dumps(model),encoding='utf-8');encoder=FakeEncoder();_ENCODERS['fake']=encoder
            msg=EmailMessage();msg.set_content('Your account will be suspended unless you verify your password now.')
            translated={'text':'계정이 정지됩니다. 지금 비밀번호를 확인하세요.','status':'translated','source_language':'en','translated':True}
            with patch('email_analyzer.text_translation.translate_context_to_korean',return_value=translated):
                result=SemanticMLEngine(path,'translation-model').analyze(msg)
            self.assertEqual(result.status,'ok')
            self.assertEqual(result.details['translation_status'],'translated')
            self.assertEqual(result.details['source_language'],'en')

if __name__=='__main__':unittest.main()
