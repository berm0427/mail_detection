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

if __name__=='__main__':unittest.main()
