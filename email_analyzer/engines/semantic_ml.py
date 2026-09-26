"""Local MiniLM classifier used as contextual evidence."""
import json,math
from pathlib import Path
from email_analyzer.evidence_features import message_text
from email_analyzer.engines.base import EngineResult

_ENCODERS={}

def preload_semantic_encoder(artifact_path):
    """Load the configured local encoder on the calling thread and cache it."""
    path=Path(artifact_path)
    artifact=json.loads(path.read_text(encoding='utf-8'))
    model_path=artifact['embedding_model_path']
    if model_path in _ENCODERS:
        return _ENCODERS[model_path]
    if not Path(model_path).is_dir():
        raise OSError(f'Embedding model directory is missing: {model_path}')
    from sentence_transformers import SentenceTransformer
    _ENCODERS[model_path]=SentenceTransformer(model_path,device='cpu')
    return _ENCODERS[model_path]

class SemanticMLEngine:
    name='semantic_ml'
    def __init__(self,path,translation_model_path=None):
        self.path=Path(path) if path else None
        self.translation_model_path=Path(translation_model_path) if translation_model_path else None
    def analyze(self,message):
        if not self.path or not self.path.is_file():return EngineResult(self.name,'skipped',error='Semantic ML model not installed')
        try:
            # Optional inference dependencies must not prevent other engines loading.
            # Keep this inside the error boundary; unavailable inference has no score.
            import numpy as np
            artifact=json.loads(self.path.read_text(encoding='utf-8'));model_path=artifact['embedding_model_path']
            encoder=preload_semantic_encoder(self.path)
            original_text=message_text(message)
            from email_analyzer.text_translation import translate_context_to_korean
            translation=translate_context_to_korean(original_text,self.translation_model_path)
            if translation['source_language'] not in ('ko','unknown') and not translation['translated']:
                status=translation['status']
                return EngineResult(
                    self.name,
                    'error' if status=='translation_error' else 'skipped',
                    details={'translation_status':status,'source_language':translation['source_language']},
                    error=f"외국어 문맥 번역을 사용할 수 없음: {status}",
                )
            vector=encoder.encode([translation['text']],convert_to_numpy=True,normalize_embeddings=True)[0]
            mean=np.asarray(artifact['mean']);scale=np.asarray(artifact['scale']);coef=np.asarray(artifact['coef'])
            if len(vector)!=len(mean) or np.any(scale<=0):raise ValueError('Invalid dimensions')
            z=float((vector-mean)/scale@coef+float(artifact['intercept']))
            score=1/(1+math.exp(-z)) if z>=0 else math.exp(z)/(1+math.exp(z))
            return EngineResult(self.name,'ok',score,{'model_id':artifact['model_id'],'predicted_label':int(score>=float(artifact.get('decision_threshold',.5))),
                'decision_threshold':float(artifact.get('decision_threshold',.5)),'training_rows':artifact.get('training_rows'),
                'role':'context_evidence','requires_objective_corroboration':True,
                'selection':'scenario_group_cv','translation_status':translation['status'],
                'source_language':translation['source_language'],'translated_to':'ko' if translation['translated'] else None})
        except (OSError,ValueError,TypeError,KeyError,ImportError,OverflowError) as exc:
            return EngineResult(self.name,'error',error=f'본문 문맥 ML 실행 실패: {type(exc).__name__}: {exc}')
