"""Conservative evidence policy: no arithmetic fusion of unrelated scores."""
import math

POLICY_VERSION = 'evidence-review-v7'
ML_REVIEW_THRESHOLD = 0.9


def _semantic_objective_signals(result, html, attachment_threats, attachment_alerts):
    """Return independently observable signals that can corroborate semantic ML."""
    signals=[]
    urls=result.get('url_analysis') or {}
    links=result.get('link_evidence') or {}
    reference=result.get('reference_evidence') or {}
    auth=((result.get('rule_result') or result).get('auth_summary') or {})
    if any((item.get('risk_score') or 0)>=10 for item in urls.get('analyzed_urls',[])):
        signals.append('url_rule')
    if (links.get('different_host_count') or 0)>0:
        signals.append('display_target_mismatch')
    if (reference.get('official_claim_mismatch_count') or 0)>0:
        signals.append('official_claim_mismatch')
    if reference.get('from_reply_relation')=='different_hosts':
        signals.append('from_reply_mismatch')
    if html.get('signals'):
        signals.append('password_submission_route')
    if auth.get('failures'):
        signals.append('authentication_failure')
    if attachment_threats:
        signals.append('attachment_threat')
    if attachment_alerts:
        signals.append('attachment_structure_alert')
    return signals


def combine_evidence(result):
    original=result.get('verdict','error')
    engines=result.get('engine_results') or {}
    unavailable=[]
    reasons=['판정 근거: 헤더·URL·HTML·도메인·첨부파일의 구조 증거와 본문 문맥 ML 결과를 결합합니다.']
    signals=[]

    def add_signal(signal_id, source, severity, summary, reflected=True, details=None):
        """Record one normalized finding without adding unlike scores together."""
        signals.append({
            'id': signal_id,
            'source': source,
            'severity': severity,
            'reflected': bool(reflected),
            'summary': summary,
            'details': details or {},
        })
    # Retained as a compatibility field for older saved results. The retired
    # baseline engine never contributes to the current decision.
    ml_review=False
    evidence_ml=engines.get('evidence_ml') or {};evidence_score=evidence_ml.get('score')
    evidence_details=evidence_ml.get('details') or {};gate=evidence_details.get('validation_gate') or {}
    evidence_valid=(evidence_ml.get('status')=='ok' and isinstance(evidence_score,(int,float)) and not isinstance(evidence_score,bool)
                    and math.isfinite(evidence_score) and 0<=evidence_score<=1 and gate.get('passed') is True)
    evidence_positive=evidence_valid and evidence_details.get('predicted_label')==1
    razor=engines.get('razor') or {}
    razor_match=razor.get('status')=='ok' and (razor.get('details') or {}).get('catalogue_match') is True
    if razor.get('status')=='ok' and type((razor.get('details') or {}).get('catalogue_match')) is not bool:
        razor_match=False
    verdict=original
    homepage=result.get('homepage_comparison') or {}
    official_domain_mismatches=homepage.get('official_domain_mismatches') or []
    if official_domain_mismatches:
        item=official_domain_mismatches[0]
        summary=f"유사 사칭 도메인: {item.get('observed_site')} → {item.get('official_site')} ({item.get('organization')})"
        add_signal('official_domain_confusable','official_site_discovery','suspicious',summary,details=item)
        reasons.append('실시간 공식 사이트 검색 결과를 기준으로 '+summary+'을 탐지했습니다.')
        if verdict in ('legitimate','inconclusive','no_signal'):
            verdict='suspicious'
    rule_result=result.get('rule_result') or result
    auth_summary=rule_result.get('auth_summary') or {}
    # A legacy baseline may exist in old saved results. It is deliberately
    # ignored and omitted from the current explanation.
    if evidence_positive:
        add_signal('evidence_ml_positive','evidence_ml','suspicious',f'구조 증거 ML 위험 점수 {evidence_score:.3f}')
        reasons.append('검증 기준을 통과한 본문·객관 증거 결합 ML이 위험 신호를 탐지했습니다.')
        if verdict in ('legitimate','inconclusive','no_signal'):verdict='suspicious'
    elif evidence_ml.get('status')=='ok' and not evidence_valid:
        reasons.append('결합 ML의 검증 기준을 확인할 수 없어 최종 판정에서 제외했습니다.')
    if razor_match:
        add_signal('razor_catalogue_match','razor','suspicious','공유 스팸 서명 카탈로그 일치')
        reasons.append('Razor 스팸 서명 일치: 주의 판정에 반영했습니다.')
        if verdict in ('legitimate','inconclusive'):verdict='suspicious'
    if auth_summary.get('failures'):
        add_signal('authentication_failure','header_authentication','suspicious',f"이메일 인증 실패 {len(auth_summary['failures'])}건",details={'failures':auth_summary['failures']})
        reasons.append('명시적인 이메일 인증 실패가 있어 기존 규칙 위험 신호로 반영했습니다.')
    from .html_review import html_review
    html = html_review(result)
    if html['signals']:
        add_signal('unsafe_password_route','html_structure','suspicious',f"위험한 비밀번호 전송 경로 {len(html['signals'])}건",details={'signals':html['signals']})
        reasons.append('HTML: 제출 대상 비밀번호 필드의 외부·HTTP·GET 전송 경로를 탐지하여 주의 판정에 반영했습니다.')
        if verdict in ('legitimate','inconclusive'):verdict='suspicious'
    attachment_scans=[(item.get('malware_scan') or {}) for item in result.get('attachments',[])]
    attachment_threats=[x for x in attachment_scans if x.get('status')=='threat_detected']
    attachment_alerts=[x for x in attachment_scans if x.get('status') in ('alert','suspicious_structure')]
    attachment_failures=[x for x in attachment_scans if x.get('status') in ('error','timeout','unavailable','disabled')]
    if attachment_threats:
        add_signal('attachment_malware','attachment_scan','dangerous',f'첨부파일 악성코드 탐지 {len(attachment_threats)}건')
        reasons.append(f'첨부파일 악성코드 탐지 {len(attachment_threats)}건: 파일을 열지 마세요.')
        verdict='dangerous'
    elif attachment_alerts:
        add_signal('attachment_structure_alert','attachment_scan','suspicious',f'첨부파일 의심 구조 {len(attachment_alerts)}건')
        reasons.append(f'첨부파일 검사 경고 {len(attachment_alerts)}건: 위협 또는 검사 오류를 확인하세요.')
        if verdict in ('legitimate','inconclusive','no_signal'):verdict='suspicious'
    if attachment_failures:
        reasons.append(f'첨부파일 검사 미완료 {len(attachment_failures)}건. 검사 실패를 악성 판정으로 계산하지 않았습니다.')
    semantic=engines.get('semantic_ml') or {};semantic_score=semantic.get('score')
    semantic_details=semantic.get('details') or {}
    semantic_valid=(semantic.get('status')=='ok' and isinstance(semantic_score,(int,float)) and not isinstance(semantic_score,bool)
                    and math.isfinite(semantic_score) and 0<=semantic_score<=1)
    semantic_positive=semantic_valid and semantic_details.get('predicted_label')==1
    objective_signals=_semantic_objective_signals(result,html,attachment_threats,attachment_alerts)
    semantic_corroborated=bool(semantic_positive and objective_signals)
    if semantic_corroborated:
        add_signal('semantic_ml_corroborated','semantic_ml','suspicious',
                   f"본문 위험 문맥과 구조 증거 일치: {', '.join(objective_signals)}",
                   details={'score':semantic_score,'objective_signals':objective_signals})
        reasons.append('본문 문맥 ML의 위험 신호가 구조 증거와 일치하여 최종 판정에 반영했습니다: '+', '.join(objective_signals)+'.')
        if verdict in ('legitimate','inconclusive','no_signal'):verdict='suspicious'
    elif semantic_positive:
        add_signal('semantic_ml_advisory','semantic_ml','advisory',f'본문 위험 문맥 점수 {semantic_score:.3f}',False)
        reasons.append('본문 문맥 ML에서 위험 문맥을 탐지했습니다. 구조 증거를 함께 표시합니다.')
    html_pair_ml=engines.get('html_pair_ml') or {};html_pair_score=html_pair_ml.get('score')
    html_pair_details=html_pair_ml.get('details') or {}
    html_pair_positive=(html_pair_ml.get('status')=='ok' and isinstance(html_pair_score,(int,float))
                        and not isinstance(html_pair_score,bool) and math.isfinite(html_pair_score)
                        and 0<=html_pair_score<=1 and html_pair_details.get('predicted_label')==1
                        and (html_pair_details.get('validation_gate') or {}).get('passed') is True)
    if html_pair_positive:
        pair=html_pair_details.get('highest_risk_pair') or {}
        add_signal('html_pair_ml_positive','html_pair_ml','suspicious',
                   f"목적지·공식 페이지 구조 위험: {pair.get('target_host')} ↔ {pair.get('reference_host')}",
                   details={'score':html_pair_score,'pair':pair})
        reasons.append(f"목적지와 실시간 검색된 공식 페이지의 HTML 구조 차이를 ML이 위험 신호로 탐지했습니다: {pair.get('target_host')} ↔ {pair.get('reference_host')}.")
        if verdict in ('legitimate','inconclusive','no_signal'):verdict='suspicious'
    rule_score=rule_result.get('risk_score', result.get('risk_score',0))
    page_analysis=result.get('page_analysis') or {}
    page_ok=any(page.get('status')=='ok' for page in page_analysis.get('pages',[]))
    reference=result.get('reference_evidence') or {}
    registered_official=any(link.get('relationship')=='registered' for link in reference.get('claimed_official_links',[]))
    established=(result.get('header') or {}).get('domain_reputation')=='established'
    complete_safe_html=html['coverage'] in ('complete','no_targets')
    corroborated_benign=(complete_safe_html or
                         (established and reference.get('official_claim_mismatch_count',0)==0 and (page_ok or registered_official)))
    weak_only=(isinstance(rule_score,(int,float)) and rule_score<10 and corroborated_benign and not auth_summary.get('failures')
               and not razor_match and not evidence_positive and not attachment_threats
               and not attachment_alerts and not attachment_failures and not html['signals'] and not semantic_corroborated and not html_pair_positive
               and not official_domain_mismatches)
    no_observed_risk=(isinstance(rule_score,(int,float)) and rule_score<10 and not auth_summary.get('failures')
                      and not razor_match and not evidence_positive and not attachment_threats and not attachment_alerts
                      and not html['signals'] and not semantic_corroborated and not html_pair_positive and not official_domain_mismatches)
    if verdict=='inconclusive' and (weak_only or no_observed_risk):
        verdict='no_signal'
        reasons.append('위험 판정 기준에 해당하는 URL·HTML·인증·첨부파일 신호가 발견되지 않았습니다.')
    elif verdict=='inconclusive' and isinstance(rule_score,(int,float)) and rule_score>=10:
        verdict='suspicious'
        reasons.append(f'규칙 기반 위험 신호가 {rule_score}점으로 확인되어 주의 판정했습니다.')
    if (isinstance(rule_score,(int,float)) and rule_score>=10
            and verdict in ('suspicious','dangerous')):
        add_signal('legacy_rule_threshold','legacy_rules',
                   'dangerous' if original=='dangerous' else 'suspicious',
                   f"규칙 위험 점수 {rule_score}/100",details={'threshold':rule_result.get('risk_threshold',70)})
    if original=='error':verdict='error'
    reflected_signals=[item for item in signals if item['reflected']]
    severity_order={'none':0,'advisory':1,'suspicious':2,'dangerous':3}
    highest_severity=max((item['severity'] for item in reflected_signals),
                         key=lambda value:severity_order.get(value,0),default='none')
    review_required=bool(ml_review or evidence_positive or semantic_corroborated or razor_match or attachment_threats or attachment_alerts or verdict in ('suspicious','dangerous','error'))
    return {'policy_version':POLICY_VERSION,'verdict':verdict,'original_verdict':original,
            'review_required':review_required,
            'html_review':html,
            'authentication_status':'failed' if auth_summary.get('failures') else 'unverified' if auth_summary.get('incomplete') else 'see_header_evidence',
            'ml_review_threshold':ML_REVIEW_THRESHOLD,'ml_advisory_only':True,
            'ml_review_signal':ml_review,'razor_match':razor_match,'unavailable_engines':unavailable,
            'evidence_ml_signal':evidence_positive,
            'semantic_ml_integrated':True,
            'semantic_ml_signal':semantic_positive,'semantic_ml_corroborated':semantic_corroborated,
            'semantic_ml_objective_signals':objective_signals,
            'html_pair_ml_signal':html_pair_positive,
            'official_domain_mismatch_signal':bool(official_domain_mismatches),
            'attachment_scan':{'threats':len(attachment_threats),'alerts':len(attachment_alerts),'failures':len(attachment_failures)},
            'signals':signals,'reflected_signal_count':len(reflected_signals),
            'highest_severity':highest_severity,
            'rule_score':rule_score,'rule_threshold':rule_result.get('risk_threshold',result.get('risk_threshold',70)),
            'reasons':reasons}
