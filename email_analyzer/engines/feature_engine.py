"""Feature extraction adapter; this engine does not assign a risk score."""
from email.message import EmailMessage

from email_analyzer.engines.base import BaseEngine, EngineResult
from email_analyzer.features.extractor import EmailFeatureExtractor


class FeatureEngine(BaseEngine):
    @property
    def name(self) -> str:
        return 'numerical_features'

    def analyze(self, email: EmailMessage) -> EngineResult:
        extractor = EmailFeatureExtractor()
        try:
            features = extractor.extract(email)
        except Exception as exc:
            return EngineResult(
                engine_name=self.name, status='error',
                error=f'Feature extraction failed ({type(exc).__name__})',
            )
        return EngineResult(
            engine_name=self.name, status='ok',
            details={
                'schema_version': extractor.SCHEMA_VERSION,
                'feature_names': list(extractor.FEATURE_NAMES),
                'features': features,
                'vector': [features[name] for name in extractor.FEATURE_NAMES],
            },
        )
