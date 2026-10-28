"""Production verdict from the learned ML probability.

* The ML verdict model (``ml_verdict_model`` in engine_config.json) decides
  whether a message is suspicious.  Its weights were learned; nothing here adds
  hand-set points.
* Antivirus and Razor outputs are observations, not ground-truth labels.  They
  are displayed for review but never override the learned verdict.
* Authentication, official-site relations, HTML, attachment structure and
  legacy rule diagnostics are also shown as reference observations only.
* Any such observation marks the result as needing user review
  (``overall_status == 'review_required'``) without changing the verdict, so the
  summary never says "no signal" while an engine has reported something.
* A missing model or missing semantic score is reported as unavailable, never
  as a low-risk result.
"""
import math

from .observations import attachment_scan_counts, collect_observations, razor_match, unavailable_engines

POLICY_VERSION = 'ml-verdict-v4'


def _ml_verdict(result):
    from .ml_verdict import analyze_ml_verdict
    from .pipeline import configured_model_path
    semantic = (result.get('engine_results') or {}).get('semantic_ml') or {}
    score = semantic.get('score')
    if not (semantic.get('status') == 'ok' and isinstance(score, (int, float)) and not isinstance(score, bool)
            and math.isfinite(score)):
        return {'status': 'unavailable', 'reason': '본문 문맥 ML 점수가 없어 ML 판정을 계산할 수 없습니다.'}
    path = configured_model_path('ml_verdict_model')
    if not path or not path.is_file():
        return {'status': 'unavailable', 'reason': 'ML 판정 모델이 설치되지 않았습니다.'}
    try:
        return {'status': 'ok', **analyze_ml_verdict(result, path, require_promoted=True)}
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return {'status': 'unavailable', 'reason': f'ML 판정 모델 오류: {type(exc).__name__}'}


def combine_evidence(result):
    original = result.get('verdict', 'error')
    engines = result.get('engine_results') or {}
    reasons = ['판정 근거: 학습된 ML 종합 위험 확률을 사용합니다. 백신·Razor·인증·HTML·첨부파일 구조 결과는 정·오탐 라벨이 확보되기 전까지 판정 미반영 관측으로 표시합니다. URL 구조 관측 자체는 정답으로 직접 반영하지 않으며, 학습된 발신자와 클릭·폼 목적지의 도메인 관계 특징은 ML 입력으로 사용합니다. 정적 리소스와 본문 텍스트 URL은 이 특징에서 제외합니다.']
    signals = []
    unavailable = unavailable_engines(result)

    def add_signal(signal_id, source, severity, summary, reflected, details=None):
        signals.append({'id': signal_id, 'source': source, 'severity': severity,
                        'reflected': bool(reflected), 'summary': summary, 'details': details or {}})

    ml = _ml_verdict(result)
    ml_positive = ml.get('status') == 'ok' and ml.get('prediction') == 1
    if ml.get('status') == 'ok':
        add_signal('ml_verdict', 'ml_verdict', 'suspicious' if ml_positive else 'none',
                   f"ML 판정 위험 확률 {ml['score']:.3f} (기준 {ml['decision_threshold']:.2f})",
                   ml_positive, details={'score': ml['score'], 'contributions': ml.get('contributions', {})})
    else:
        unavailable.append('ml_verdict')
        reasons.append(ml['reason'])

    if original == 'error':
        verdict = 'error'
    elif ml_positive:
        verdict = 'suspicious'
        reasons.append('ML 판정 확률이 기준 이상이어서 주의 판정했습니다.')
    elif ml.get('status') == 'ok':
        verdict = 'no_signal'
        reasons.append('ML 판정 확률이 기준 미만입니다. 아래 관측 결과는 이 판정을 자동 변경하지 않습니다.')
    else:
        verdict = 'inconclusive'

    # Observations never change the verdict; any of them requests user review.
    observations = collect_observations(result)
    for item in observations:
        add_signal(item['id'], item['source'], 'advisory', item['summary'], False, details=item['details'])
    counts = attachment_scan_counts(result)
    if counts['failures']:
        reasons.append(f"첨부파일 검사 미완료 {counts['failures']}건. 검사 실패를 악성으로 계산하지 않았습니다.")
    semantic = engines.get('semantic_ml') or {}
    if semantic.get('status') == 'ok' and isinstance(semantic.get('score'), (int, float)):
        add_signal('semantic_ml_score', 'semantic_ml', 'advisory',
                   f"본문 문맥 위험 점수 {semantic['score']:.3f}", False)

    if verdict == 'no_signal' and observations:
        overall_status = 'review_required'
        reasons.append(f'ML 판정은 기준 미만이지만 검토가 필요한 관측 {len(observations)}건이 있습니다.')
    else:
        overall_status = verdict
    review_required = bool(observations) or verdict in ('suspicious', 'error', 'inconclusive')

    from .html_review import html_review
    auth_summary = ((result.get('rule_result') or result).get('auth_summary') or {})
    rule_result = result.get('rule_result') or result
    reflected_signals = [item for item in signals if item['reflected']]
    severity_order = {'none': 0, 'advisory': 1, 'suspicious': 2, 'dangerous': 3}
    highest_severity = max((item['severity'] for item in reflected_signals),
                           key=lambda value: severity_order.get(value, 0), default='none')
    return {'policy_version': POLICY_VERSION, 'verdict': verdict, 'original_verdict': original,
            'overall_status': overall_status,
            'review_required': review_required,
            'review_observations': [item['id'] for item in observations],
            'ml_verdict': ml,
            'html_review': html_review(result),
            'authentication_status': 'failed' if auth_summary.get('failures') else 'unverified' if auth_summary.get('incomplete') else 'see_header_evidence',
            'razor_match': razor_match(result), 'unavailable_engines': unavailable,
            'attachment_scan': counts,
            'signals': signals, 'reflected_signal_count': len(reflected_signals),
            'highest_severity': highest_severity,
            'rule_score': rule_result.get('risk_score', result.get('risk_score', 0)),
            'rule_threshold': rule_result.get('risk_threshold', result.get('risk_threshold', 70)),
            'reasons': reasons}
