"""Review-worthy observations read directly from raw analyzer output.

These are engine outputs, not ground-truth labels.  The production decision
shows them and uses them to request user review; the experimental fusion paths
consume them as inputs.  Nothing here reads the production verdict or any
``reflected`` flag, so changing the decision policy cannot silently change what
the research paths see.
"""

from __future__ import annotations

from email_analyzer.html_review import html_review

FAILED_SCAN_STATUSES = ('error', 'timeout', 'unavailable', 'disabled')


def attachment_scan_counts(result: dict) -> dict:
    scans = [(item.get('malware_scan') or {}) for item in result.get('attachments') or []]
    return {
        'threats': sum(scan.get('status') == 'threat_detected' for scan in scans),
        'alerts': sum(scan.get('status') in ('alert', 'suspicious_structure') for scan in scans),
        'failures': sum(scan.get('status') in FAILED_SCAN_STATUSES for scan in scans),
    }


def razor_match(result: dict) -> bool:
    razor = (result.get('engine_results') or {}).get('razor') or {}
    return razor.get('status') == 'ok' and (razor.get('details') or {}).get('catalogue_match') is True


def html_pair_positive(result: dict) -> bool:
    engine = (result.get('engine_results') or {}).get('html_pair_ml') or {}
    details = engine.get('details') or {}
    return (engine.get('status') == 'ok' and details.get('predicted_label') == 1
            and (details.get('validation_gate') or {}).get('passed') is True)


def collect_observations(result: dict) -> list[dict]:
    """Return one entry per review-worthy observation, in display order."""
    rows = []

    def add(observation_id, source, summary, details=None):
        rows.append({'id': observation_id, 'source': source, 'summary': summary, 'details': details or {}})

    counts = attachment_scan_counts(result)
    if counts['threats']:
        add('attachment_antivirus_report', 'attachment_scan', f"첨부파일 백신 엔진 위협 보고 {counts['threats']}건")
    if razor_match(result):
        add('razor_catalogue_match', 'razor', '공유 스팸 서명 카탈로그 일치')
    homepage = result.get('homepage_comparison') or {}
    for item in homepage.get('official_domain_mismatches') or []:
        add('official_domain_confusable', 'official_site_discovery',
            f"유사 사칭 도메인: {item.get('observed_site')} → {item.get('official_site')} ({item.get('organization')})", item)
    for item in homepage.get('official_external_action_routes') or []:
        add('official_claim_external_route', 'official_site_discovery',
            f"기관 주장과 무관한 클릭 경로: {item.get('organization')} → {item.get('target_host')}", item)
    auth = ((result.get('rule_result') or result).get('auth_summary') or {})
    if auth.get('failures'):
        add('authentication_failure', 'header_authentication', f"이메일 인증 실패 {len(auth['failures'])}건",
            {'failures': auth['failures']})
    html = html_review(result)
    if html['signals']:
        add('unsafe_password_route', 'html_structure', f"위험한 비밀번호 전송 경로 {len(html['signals'])}건",
            {'signals': html['signals']})
    if counts['alerts']:
        add('attachment_structure_alert', 'attachment_scan', f"첨부파일 의심 구조 {counts['alerts']}건")
    if html_pair_positive(result):
        engine = (result.get('engine_results') or {}).get('html_pair_ml') or {}
        pair = (engine.get('details') or {}).get('highest_risk_pair') or {}
        add('html_pair_ml_positive', 'html_pair_ml',
            f"목적지 URL·공식 페이지 구조 위험: {pair.get('target_host')} ↔ {pair.get('reference_host')}",
            {'score': engine.get('score'), 'pair': pair})
    return rows


def unavailable_engines(result: dict) -> list[str]:
    """Engines that ran and failed; skipped/unconfigured engines are not listed."""
    engines = result.get('engine_results') or {}
    names = []
    for name in ('semantic_ml', 'razor', 'html_pair_ml'):
        if (engines.get(name) or {}).get('status') == 'error':
            names.append(name)
    return names
