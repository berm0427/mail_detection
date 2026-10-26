"""Production verdict: learned ML probability plus external malware/spam detections.

* The ML verdict model (``ml_verdict_model`` in engine_config.json) decides
  whether a message is suspicious.  Its weights were learned; nothing here adds
  hand-set points.
* An antivirus threat detection or a Razor catalogue match is a confirmation
  from an external detector that the training data could not contain.  Either
  raises the verdict to at least ``suspicious``; together with a positive ML
  verdict it raises it to ``dangerous``.
* Every other observation (authentication, official-site relations, HTML,
  attachment structure, legacy rule diagnostics) is shown as reference only.
* A missing model or missing semantic score is reported as unavailable, never
  as a low-risk result.
"""
import math

POLICY_VERSION = 'ml-verdict-v1'


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
        return {'status': 'ok', **analyze_ml_verdict(result, path)}
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return {'status': 'unavailable', 'reason': f'ML 판정 모델 오류: {type(exc).__name__}'}


def combine_evidence(result):
    original = result.get('verdict', 'error')
    engines = result.get('engine_results') or {}
    reasons = ['판정 근거: 학습된 ML 판정 확률과 백신·Razor 외부 탐지 결과를 사용합니다. 그 밖의 관측은 참고로 표시합니다.']
    signals = []
    unavailable = []

    def add_signal(signal_id, source, severity, summary, reflected, details=None):
        signals.append({'id': signal_id, 'source': source, 'severity': severity,
                        'reflected': bool(reflected), 'summary': summary, 'details': details or {}})

    # --- decisive inputs -------------------------------------------------
    ml = _ml_verdict(result)
    ml_positive = ml.get('status') == 'ok' and ml.get('prediction') == 1
    if ml.get('status') == 'ok':
        add_signal('ml_verdict', 'ml_verdict', 'suspicious' if ml_positive else 'none',
                   f"ML 판정 위험 확률 {ml['score']:.3f} (기준 {ml['decision_threshold']:.2f})",
                   ml_positive, details={'score': ml['score'], 'contributions': ml.get('contributions', {})})
    else:
        unavailable.append('ml_verdict')
        reasons.append(ml['reason'])

    attachment_scans = [(item.get('malware_scan') or {}) for item in result.get('attachments', [])]
    attachment_threats = [x for x in attachment_scans if x.get('status') == 'threat_detected']
    attachment_alerts = [x for x in attachment_scans if x.get('status') in ('alert', 'suspicious_structure')]
    attachment_failures = [x for x in attachment_scans if x.get('status') in ('error', 'timeout', 'unavailable', 'disabled')]
    if attachment_threats:
        add_signal('attachment_malware', 'attachment_scan', 'dangerous',
                   f'첨부파일 백신 악성코드 탐지 {len(attachment_threats)}건', True)
    if attachment_failures:
        reasons.append(f'첨부파일 검사 미완료 {len(attachment_failures)}건. 검사 실패를 악성으로 계산하지 않았습니다.')

    razor = engines.get('razor') or {}
    razor_match = razor.get('status') == 'ok' and (razor.get('details') or {}).get('catalogue_match') is True
    if razor_match:
        add_signal('razor_catalogue_match', 'razor', 'suspicious', '공유 스팸 서명 카탈로그 일치', True)
    elif razor.get('status') == 'error':
        unavailable.append('razor')

    external_detection = bool(attachment_threats or razor_match)
    if original == 'error':
        verdict = 'error'
    elif external_detection and ml_positive:
        verdict = 'dangerous'
        reasons.append('외부 탐지(백신·Razor)와 ML 판정이 모두 위험을 가리켜 위험으로 판정했습니다.')
    elif external_detection or ml_positive:
        verdict = 'suspicious'
        reasons.append('외부 탐지(백신·Razor)로 주의 판정했습니다.' if external_detection
                       else 'ML 판정 확률이 기준 이상이어서 주의 판정했습니다.')
    elif ml.get('status') == 'ok':
        verdict = 'no_signal'
        reasons.append('ML 판정 확률이 기준 미만이고 백신·Razor 탐지가 없습니다.')
    else:
        verdict = 'inconclusive'

    # --- reference observations (never change the verdict) ---------------
    homepage = result.get('homepage_comparison') or {}
    for item in homepage.get('official_domain_mismatches') or []:
        add_signal('official_domain_confusable', 'official_site_discovery', 'advisory',
                   f"유사 사칭 도메인: {item.get('observed_site')} → {item.get('official_site')} ({item.get('organization')})",
                   False, details=item)
    for item in homepage.get('official_external_action_routes') or []:
        add_signal('official_claim_external_route', 'official_site_discovery', 'advisory',
                   f"기관 주장과 무관한 클릭 경로: {item.get('organization')} → {item.get('target_host')}",
                   False, details=item)
    auth_summary = ((result.get('rule_result') or result).get('auth_summary') or {})
    if auth_summary.get('failures'):
        add_signal('authentication_failure', 'header_authentication', 'advisory',
                   f"이메일 인증 실패 {len(auth_summary['failures'])}건", False,
                   details={'failures': auth_summary['failures']})
    from .html_review import html_review
    html = html_review(result)
    if html['signals']:
        add_signal('unsafe_password_route', 'html_structure', 'advisory',
                   f"위험한 비밀번호 전송 경로 {len(html['signals'])}건", False, details={'signals': html['signals']})
    if attachment_alerts:
        add_signal('attachment_structure_alert', 'attachment_scan', 'advisory',
                   f'첨부파일 의심 구조 {len(attachment_alerts)}건', False)
    semantic = engines.get('semantic_ml') or {}
    if semantic.get('status') == 'ok' and isinstance(semantic.get('score'), (int, float)):
        add_signal('semantic_ml_score', 'semantic_ml', 'advisory',
                   f"본문 문맥 위험 점수 {semantic['score']:.3f}", False)
    elif semantic:
        unavailable.append('semantic_ml')
    html_pair_ml = engines.get('html_pair_ml') or {}
    html_pair_details = html_pair_ml.get('details') or {}
    if html_pair_ml.get('status') == 'ok' and html_pair_details.get('predicted_label') == 1:
        pair = html_pair_details.get('highest_risk_pair') or {}
        add_signal('html_pair_ml_positive', 'html_pair_ml', 'advisory',
                   f"목적지 URL·공식 페이지 구조 위험: {pair.get('target_host')} ↔ {pair.get('reference_host')}",
                   False, details={'score': html_pair_ml.get('score'), 'pair': pair})
    elif html_pair_ml.get('status') == 'error':
        unavailable.append('html_pair_ml')

    rule_result = result.get('rule_result') or result
    reflected_signals = [item for item in signals if item['reflected']]
    severity_order = {'none': 0, 'advisory': 1, 'suspicious': 2, 'dangerous': 3}
    highest_severity = max((item['severity'] for item in reflected_signals),
                           key=lambda value: severity_order.get(value, 0), default='none')
    return {'policy_version': POLICY_VERSION, 'verdict': verdict, 'original_verdict': original,
            'review_required': verdict in ('suspicious', 'dangerous', 'error', 'inconclusive'),
            'ml_verdict': ml,
            'html_review': html,
            'authentication_status': 'failed' if auth_summary.get('failures') else 'unverified' if auth_summary.get('incomplete') else 'see_header_evidence',
            'razor_match': razor_match, 'unavailable_engines': unavailable,
            'attachment_scan': {'threats': len(attachment_threats), 'alerts': len(attachment_alerts),
                                'failures': len(attachment_failures)},
            'signals': signals, 'reflected_signal_count': len(reflected_signals),
            'highest_severity': highest_severity,
            'rule_score': rule_result.get('risk_score', result.get('risk_score', 0)),
            'rule_threshold': rule_result.get('risk_threshold', result.get('risk_threshold', 70)),
            'reasons': reasons}
