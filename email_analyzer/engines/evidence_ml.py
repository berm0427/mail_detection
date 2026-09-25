"""Portable hybrid model over hashed message text and objective evidence."""
import json,math
from pathlib import Path
from email_analyzer.evidence_features import EvidenceFeatureExtractor,message_text,hashed_char_ngrams
from email_analyzer.engines.base import EngineResult


class EvidenceMLEngine:
    name='evidence_ml'
    def __init__(self,path):self.path=Path(path) if path else None
    def analyze(self,message,result):
        if not self.path or not self.path.is_file():return EngineResult(self.name,'skipped',error='Evidence ML model not installed')
        try:
            model=json.loads(self.path.read_text(encoding='utf-8'));extractor=EvidenceFeatureExtractor()
            if model['schema_version']!=extractor.SCHEMA_VERSION or model['feature_names']!=list(extractor.FEATURE_NAMES):raise ValueError('Feature schema mismatch')
            bins=int(model['text_bins']);text_coef=model['text_coef'];dense=extractor.vector(result)
            if bins!=len(text_coef) or any(len(model[k])!=len(dense) for k in ('mean','scale','evidence_coef')):raise ValueError('Invalid dimensions')
            arrays=[model[k] for k in ('mean','scale','evidence_coef')]
            if any(not math.isfinite(float(v)) for a in arrays+[text_coef] for v in a) or not math.isfinite(float(model['intercept'])):raise ValueError('Non-finite parameters')
            if any(float(v)<=0 for v in model['scale']):raise ValueError('Invalid scale')
            z=float(model['intercept'])+sum((x-m)/s*c for x,m,s,c in zip(dense,*arrays))
            if bins:
                for index,value in hashed_char_ngrams(message_text(message),bins).items():z+=value*text_coef[index]
            score=1/(1+math.exp(-z)) if z>=0 else math.exp(z)/(1+math.exp(z))
            return EngineResult(self.name,'ok',score,{'model_id':model['model_id'],'positive_class':model['positive_class'],
                'predicted_label':int(score>=float(model.get('decision_threshold',.5))),
                'schema_version':model['schema_version'],'validation_gate':model.get('validation_gate')})
        except (OSError,ValueError,TypeError,KeyError,OverflowError) as exc:
            return EngineResult(self.name,'error',error=f'Evidence ML inference failed: {type(exc).__name__}')
