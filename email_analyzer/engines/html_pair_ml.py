"""Classifier for a fetched destination page versus a verified official page."""
import json
import math
from pathlib import Path

from email_analyzer.engines.base import EngineResult
from email_analyzer.html_pair_features import FEATURE_NAMES, SCHEMA_VERSION


class HtmlPairMLEngine:
    name = 'html_pair_ml'

    def __init__(self, path):
        self.path = Path(path) if path else None

    def analyze(self, homepage_comparison):
        if not self.path or not self.path.is_file():
            return EngineResult(self.name, 'skipped', error='HTML pair model not installed')
        try:
            model = json.loads(self.path.read_text(encoding='utf-8'))
            if model['schema_version'] != SCHEMA_VERSION or model['feature_names'] != list(FEATURE_NAMES):
                raise ValueError('Feature schema mismatch')
            gate = model.get('validation_gate') or {}
            if gate.get('passed') is not True:
                raise ValueError('Validation gate not passed')
            mean, scale, coefficients = (model[key] for key in ('mean', 'scale', 'coef'))
            if not (len(mean) == len(scale) == len(coefficients) == len(FEATURE_NAMES)):
                raise ValueError('Invalid dimensions')
            if any(float(value) <= 0 for value in scale):
                raise ValueError('Invalid scale')
            observations = []
            for comparison in (homepage_comparison or {}).get('comparisons', []):
                features = comparison.get('features') or {}
                if any(name not in features for name in FEATURE_NAMES):
                    continue
                vector = [float(features[name]) for name in FEATURE_NAMES]
                z = float(model['intercept']) + sum(
                    (value - float(center)) / float(width) * float(weight)
                    for value, center, width, weight in zip(vector, mean, scale, coefficients)
                )
                score = 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))
                observations.append({
                    'target_host': comparison.get('target_host'),
                    'reference_host': comparison.get('reference_host'),
                    'score': score,
                })
            if not observations:
                return EngineResult(self.name, 'skipped', error='No verified target/reference HTML pair')
            highest = max(observations, key=lambda item: item['score'])
            threshold = float(model.get('decision_threshold', 0.5))
            return EngineResult(self.name, 'ok', highest['score'], {
                'model_id': model['model_id'],
                'predicted_label': int(highest['score'] >= threshold),
                'decision_threshold': threshold,
                'validation_gate': gate,
                'highest_risk_pair': highest,
                'pairs': observations,
                'role': 'destination_url_and_official_html_structure_evidence',
            })
        except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
            return EngineResult(self.name, 'error', error=f'HTML 구조 ML 실행 실패: {type(exc).__name__}: {exc}')
