import json
import os
import sys
from email.message import EmailMessage
from pathlib import Path

os.environ.setdefault('EMAIL_DISABLE_REMOTE_AI', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_analyzer.decision import combine_evidence
from email_analyzer.engine_view import engine_rows, decision_text
from email_analyzer.legacy_rules import annotate_auth_evidence, score_rules


OUT = ROOT / 'analysis_result' / 'auth-evidence-fix_20260918T0033'


def message(name, auth=None, body='Synthetic auth evidence validation.'):
    msg = EmailMessage()
    msg['From'] = f'{name} <sender@example.org>'
    msg['To'] = 'user@example.net'
    msg['Subject'] = f'auth evidence {name}'
    if auth:
        msg['Authentication-Results'] = auth
    msg.set_content(body)
    return msg


def run_case(name, header, msg, body=None, url=None, brand=None):
    annotated = annotate_auth_evidence(header, msg)
    rule = score_rules(annotated, body or {'total_matches': 0, 'categories': {}}, url or {}, brand or {})
    result = {
        'verdict': rule['verdict'],
        'risk_score': rule['risk_score'],
        'risk_threshold': rule['risk_threshold'],
        'rule_result': rule,
        'engine_results': {
            'numerical_features': {'status': 'ok'},
            'ml_baseline': {'status': 'ok', 'score': 0.1},
            'razor': {'status': 'ok', 'details': {'catalogue_match': False}},
        },
    }
    result['decision'] = combine_evidence(result)
    result['verdict'] = result['decision']['verdict']
    result['engine_rows'] = engine_rows(result)
    result['decision_text'] = decision_text(result)
    return result


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'README.md').write_text(
        '# Authentication evidence synthetic verification\n\n'
        'Re-run from project root with:\n\n'
        '```cmd\n'
        'set EMAIL_DISABLE_REMOTE_AI=1&& "C:\\Users\\berm0\\Documents\\Codex\\2026-09-11\\x20\\work\\analysis-venv\\Scripts\\python.exe" -B tests\\auth_evidence_synthetic_check.py\n'
        '```\n',
        encoding='utf-8',
    )
    cases = {
        'missing_auth': run_case('missing_auth', {}, message('missing_auth')),
        'explicit_fail': run_case(
            'explicit_fail',
            {'spf_check': 'fail', 'dkim_check': 'fail', 'dmarc_check': 'fail'},
            message('explicit_fail', 'mx.example; spf=fail dkim=fail dmarc=fail'),
        ),
        'unverified_pass_header': run_case(
            'unverified_pass_header',
            {'spf_check': 'pass', 'dkim_check': 'pass', 'dmarc_check': 'pass'},
            message('unverified_pass_header', 'mx.example; spf=pass dkim=pass dmarc=pass'),
        ),
        'verified_pass_internal': run_case(
            'verified_pass_internal',
            {'spf_check': 'pass', 'dkim_check': 'pass', 'dmarc_check': 'pass'},
            message('verified_pass_internal'),
        ),
        'lookup_error': run_case(
            'lookup_error',
            {'spf_check': 'temperror', 'dkim_check': 'permerror', 'dmarc_check': 'error'},
            message('lookup_error'),
        ),
        'missing_auth_with_url_risk': run_case(
            'missing_auth_with_url_risk',
            {},
            message('missing_auth_with_url_risk', body='Click https://evil.example/login now.'),
            body={'total_matches': 1, 'categories': {'malicious': {'count': 1}}},
            url={'risk_score': 30},
        ),
    }
    output = OUT / 'auth_evidence_synthetic_results.json'
    output.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding='utf-8')
    print(output)
    for name, result in cases.items():
        print(name, result['risk_score'], result['verdict'], result['rule_result']['auth_summary'])


if __name__ == '__main__':
    main()
