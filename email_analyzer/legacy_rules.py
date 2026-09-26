"""Existing rule score, shared by the GUI pipeline and offline comparison.

Authentication evidence is intentionally conservative.  A missing header,
softfail/neutral/none, or DNS lookup error is not a verified pass and not an
explicit failure.  Those states are carried as limitations so the caller can
avoid presenting the result as safe.
"""

import re

AUTH_METHODS = (
    ('spf_check', 'SPF', 15),
    ('dkim_check', 'DKIM', 15),
    ('dmarc_check', 'DMARC', 5),
)

PASS_STATUSES = {'pass', 'match', 'verified_pass'}
FAIL_STATUSES = {'fail', 'hardfail', 'mismatch'}
MISSING_STATUSES = {
    '', 'unknown', 'missing', 'none', 'neutral', 'softfail', 'no_reference',
    'no_ip', 'not_applicable', 'unverified_pass', 'observed',
    'observed_signature', 'arc_pass', 'arc_none', 'arc_missing',
    'arc_observed',
    'recomputed_pass_untrusted_input', 'recomputed_fail_untrusted_input',
    'recomputed_softfail_untrusted_input', 'recomputed_neutral_untrusted_input',
    'recomputed_none_untrusted_input', 'recomputed_error_untrusted_input',
}
ERROR_STATUSES = {'error', 'temperror', 'permerror', 'timeout', 'lookup_error', 'dns_error'}


def _clean_status(value):
    return str(value or '').strip().lower()


def classify_auth_status(value):
    """Classify one authentication observation for rule scoring."""
    status = _clean_status(value)
    if status in PASS_STATUSES:
        return 'pass'
    if status in FAIL_STATUSES or status.startswith('arc_fail') or status == 'unverified_fail':
        return 'fail'
    if status in ERROR_STATUSES or status.startswith('arc_temperror') or status.startswith('arc_permerror'):
        return 'error'
    if status in MISSING_STATUSES or status.startswith('arc_'):
        return 'missing'
    return 'missing'


def annotate_auth_evidence(header, message=None):
    """Attach source/trust metadata and normalize unverified pass-like headers.

    Current parsing cannot prove that Authentication-Results/ARC/Received-SPF
    came from a trusted local boundary.  Therefore pass-like values that appear
    to come only from message headers are downgraded to ``unverified_pass``;
    explicit failure values remain risk signals.
    """
    updated = dict(header or {})
    existing_evidence = dict(updated.get('auth_evidence') or {})
    source_map = dict(existing_evidence.get('source') or {})
    original = {key: updated.get(key, 'unknown') for key, _, _ in AUTH_METHODS}
    observations = {
        'authentication_results_present': False,
        'arc_authentication_results_present': False,
        'received_spf_present': False,
        'dkim_signature_present': False,
        'dmarc_result_present': False,
        'pass_headers_trusted': False,
    }
    if message is not None:
        observations.update({
            'authentication_results_present': bool(message.get_all('Authentication-Results', [])),
            'arc_authentication_results_present': bool(message.get_all('ARC-Authentication-Results', [])),
            'received_spf_present': bool(message.get_all('Received-SPF', [])),
            'dkim_signature_present': bool(message.get_all('DKIM-Signature', [])),
            'dmarc_result_present': bool(message.get_all('DMARC-Result', [])),
        })
    # Record only method/result tokens, never treat an assertion as verification.
    asserted = {key: [] for key, _, _ in AUTH_METHODS}
    if message is not None:
        for value in message.get_all('Authentication-Results', []):
            # Comments and quoted strings can contain examples, not assertions.
            value = str(value)
            for _ in range(8):
                value = re.sub(r'\([^()]*\)', '', value)
            value = re.sub(r'"(?:\\.|[^"\\])*"', '', value)
            for method, status in re.findall(r'(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b', value, re.I):
                asserted[method.lower() + '_check'].append(status.lower())
    raw_header_seen = {
        'spf_check': observations['received_spf_present'] or observations['authentication_results_present'] or observations['arc_authentication_results_present'],
        'dkim_check': observations['authentication_results_present'] or observations['arc_authentication_results_present'] or observations['dkim_signature_present'],
        'dmarc_check': observations['authentication_results_present'] or observations['arc_authentication_results_present'] or observations['dmarc_result_present'],
    }
    for key, _, _ in AUTH_METHODS:
        status = _clean_status(updated.get(key))
        source = source_map.get(key)
        values = asserted[key]
        if source != 'local_verification' and status in {'', 'unknown', 'missing', 'none'} and values:
            updated[key] = 'unverified_pass' if all(v == 'pass' for v in values) else 'observed'
        if source != 'local_verification':
            if status in {'pass', 'match', 'verified_pass'}:
                updated[key] = 'unverified_pass'
            elif status in FAIL_STATUSES:
                updated[key] = 'unverified_fail'
    normalized = {key: updated.get(key, 'unknown') for key, _, _ in AUTH_METHODS}
    updated['auth_evidence'] = {
        'header_assertions': asserted,
        'original': original,
        'normalized': normalized,
        'source': {key: source_map.get(key, 'raw_message_header' if raw_header_seen[key] else 'not_observed') for key, _, _ in AUTH_METHODS},
        'raw_header_observations': observations,
        'note': 'Authentication-Results/ARC/Received-SPF pass/fail-like headers are raw observations unless a trusted local verification source is recorded.',
    }
    return updated


def _auth_summary(header):
    failures, limitations, errors = [], [], []
    for key, title, points in AUTH_METHODS:
        status = _clean_status(header.get(key))
        category = classify_auth_status(status)
        if category == 'fail':
            failures.append({'method': title, 'status': status, 'points': points})
        elif category == 'error':
            errors.append({'method': title, 'status': status})
        elif category == 'missing':
            limitations.append({'method': title, 'status': status or 'missing'})
    return {
        'failures': failures,
        'limitations': limitations,
        'errors': errors,
        'incomplete': bool(limitations or errors),
        'all_passed': not failures and not limitations and not errors,
    }


def score_rules(header, body, url, brand, reference=None):
    score, reasons = 0, []
    header = header or {}
    auth = _auth_summary(header)
    for failure in auth['failures']:
        score += failure['points']
        reasons.append(f"{failure['method']} 명시적 인증 실패({failure['status']}): +{failure['points']}")
    if header.get('domain_reputation') == 'suspicious':
        score += 25; reasons.append('도메인 평판 의심: +25')
    claim_mismatches = int((reference or {}).get('official_claim_mismatch_count', 0) or 0)
    if claim_mismatches:
        points = min(claim_mismatches * 30, 30)
        score += points; reasons.append(f'공식 기관 링크 주장과 목적지 도메인 불일치 {claim_mismatches}건: +{points}')
    score=min(score,100)
    if score >= 70:
        verdict = 'dangerous'
    elif score >= 25 or auth['failures']:
        verdict = 'suspicious'
    elif auth['incomplete']:
        verdict = 'inconclusive'
    else:
        verdict = 'legitimate'
    return {'risk_score':score,'risk_threshold':70,
            'verdict':verdict,
            'reasons':reasons,
            'auth_summary':auth,
            'auth_evidence':header.get('auth_evidence', {})}


def auth_observation_lines(evidence):
    lines = []
    for key, label, _ in AUTH_METHODS:
        values = (evidence.get('header_assertions') or {}).get(key) or []
        if values:
            lines.append(f"{label} 원문 Authentication-Results 관측: {', '.join(values)} · 발행 출처 확인 자료 없음 · 인증 판정에서 제외")
    return lines
