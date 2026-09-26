import contextlib
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid
from email.message import EmailMessage
from pathlib import Path

os.environ['EMAIL_DISABLE_REMOTE_AI'] = '1'
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def default_run_root():
    stamp = time.strftime('%Y%m%dT%H%M%S')
    return ROOT / 'analysis_result' / f'test-isolation-hardening_{stamp}_{uuid.uuid4().hex[:8]}'


RUN_ROOT = Path(os.environ.get('REAL_ANALYZER_GUI_OUT') or default_run_root())
if not RUN_ROOT.is_absolute():
    RUN_ROOT = ROOT / RUN_ROOT
INPUT_DIR = RUN_ROOT / 'inputs'
RESULTS_DIR = RUN_ROOT / 'results'


def sha256(path):
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def make_message(path, subject, body, auth=None, attachment=False):
    msg = EmailMessage()
    msg['From'] = 'Synthetic Sender <sender@example.org>'
    msg['To'] = 'user@example.net'
    msg['Subject'] = subject
    if auth:
        msg['Authentication-Results'] = auth
    msg.set_content(body)
    if attachment:
        msg.add_attachment(b'inert attachment bytes', maintype='application', subtype='octet-stream', filename='sample.txt')
    path.write_bytes(msg.as_bytes())
    return path


@contextlib.contextmanager
def patched_external_boundaries():
    from mail_header.mail_header_detection_v4 import EmailHeaderAnalyzer

    original_whois = EmailHeaderAnalyzer.check_whois_info
    original_dns = EmailHeaderAnalyzer.check_dns_records
    original_compare = EmailHeaderAnalyzer.compare_ip_lists

    def no_whois(self, domain):
        self.analysis_result.setdefault('details', {})['domain_info'] = {'source': 'test_stub'}
        self.analysis_result['domain_reputation'] = 'unknown'

    def no_dns(self, domain):
        self.analysis_result['spf_check'] = self.analysis_result.get('spf_check', 'unknown')
        self.analysis_result.setdefault('details', {})['dns_stubbed'] = True

    def no_compare(self):
        if self.analysis_result.get('spf_check') not in ('fail', 'mismatch'):
            self.analysis_result['spf_check'] = self.analysis_result.get('spf_check', 'unknown')

    EmailHeaderAnalyzer.check_whois_info = no_whois
    EmailHeaderAnalyzer.check_dns_records = no_dns
    EmailHeaderAnalyzer.compare_ip_lists = no_compare
    try:
        yield
    finally:
        EmailHeaderAnalyzer.check_whois_info = original_whois
        EmailHeaderAnalyzer.check_dns_records = original_dns
        EmailHeaderAnalyzer.compare_ip_lists = original_compare


def razor_command(kind):
    code = {
        'match': 'import sys; sys.exit(0)',
        'miss': 'import sys; sys.exit(1)',
        'error': 'import sys; sys.exit(255)',
        'timeout': 'import time; time.sleep(3)',
    }[kind]
    return [sys.executable, '-c', code]


def run_gui_case(eml_path, runtime_options, timeout_ms=20000):
    from PyQt5.QtCore import QEventLoop, QTimer
    from PyQt5.QtWidgets import QApplication
    from main_gui import EmailAnalyzerGUI

    app = QApplication.instance() or QApplication([])
    window = EmailAnalyzerGUI()
    window.runtime_options = dict(runtime_options)
    window.file_path_edit.setText(str(eml_path))
    window.start_analysis()
    loop = QEventLoop()
    timer = QTimer(); timer.setSingleShot(True); timer.timeout.connect(loop.quit)
    if window.analysis_thread:
        window.analysis_thread.finished.connect(loop.quit)
    timer.start(timeout_ms)
    loop.exec_()
    if window.analysis_thread and window.analysis_thread.isRunning():
        window.analysis_thread.terminate(); window.analysis_thread.wait(1000)
        raise TimeoutError(f'GUI analysis timed out for {eml_path}')
    settle = QEventLoop(); QTimer.singleShot(100, settle.quit); settle.exec_()
    QApplication.processEvents()
    result_root = Path(runtime_options['analysis_result_root'])
    matches = sorted(result_root.glob(f'{eml_path.stem}_*'), key=lambda p: p.stat().st_mtime)
    result_dir = matches[-1]
    final_json = result_dir / 'final_analysis_result.json'
    summary_text = window.summary_text.toPlainText()
    log_text = window.log_text.toPlainText()
    if final_json.exists():
        result = json.loads(final_json.read_text(encoding='utf-8'))
    else:
        error_path = result_dir / 'gui_error_capture.txt'
        error_path.write_text(summary_text + '\n\n[LOG]\n' + log_text, encoding='utf-8')
        result = {'verdict': 'error', 'decision': {}, 'engine_results': {}, 'rule_result': {}, 'error': summary_text, 'error_capture': str(error_path.relative_to(ROOT))}
    gui_rows = []
    for r in range(window.engine_table.rowCount()):
        gui_rows.append([window.engine_table.item(r, c).text() if window.engine_table.item(r, c) else '' for c in range(window.engine_table.columnCount())])
    return {
        'success_status': window.status_label.text(),
        'button_enabled': window.analyze_button.isEnabled(),
        'progress_value': window.progress_bar.value(),
        'result_dir': str(result_dir.relative_to(ROOT)),
        'final_json': str(final_json.relative_to(ROOT)),
        'verdict': result.get('verdict'),
        'review_required': (result.get('decision') or {}).get('review_required'),
        'policy_version': (result.get('decision') or {}).get('policy_version'),
        'engine_statuses': {k: v.get('status') for k, v in (result.get('engine_results') or {}).items()},
        'rule_auth_summary': (result.get('rule_result') or {}).get('auth_summary'),
        'gui_rows': gui_rows,
        'error': result.get('error'),
        'error_capture': result.get('error_capture'),
    }


def main():
    # Match the supported GUI launcher: load the native semantic runtime before
    # importing header/GUI modules that may load other Windows DLLs.
    from email_analyzer.engines.semantic_ml import preload_semantic_encoder
    import json
    configured = json.loads((ROOT / 'engine_config.json').read_text(encoding='utf-8'))['semantic_ml_model']
    preload_semantic_encoder(ROOT / configured)
    RUN_ROOT.mkdir(parents=True, exist_ok=False)
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    kb = ROOT / 'phishing_knowledge_base.pkl'
    before = {'exists': kb.exists(), 'sha256': sha256(kb)}
    with tempfile.TemporaryDirectory(prefix='real-gui-isolated-') as temp:
        temp = Path(temp)
        isolated_kb = temp / 'isolated_kb.pkl'
        runtime = {
            'knowledge_base_path': str(isolated_kb),
            'allow_knowledge_base_save': False,
            'disable_network': True,
            'disable_nlp_models': True,
            'analysis_result_root': str(RESULTS_DIR),
            'engine_config_override': {'razor_command': razor_command('miss'), 'razor_timeout': 1},
        }
        cases = {
            'missing_auth': make_message(INPUT_DIR / 'missing_auth.eml', 'missing auth', 'Ordinary synthetic message.'),
            'forged_pass': make_message(INPUT_DIR / 'forged_pass.eml', 'forged pass', 'Message with forged auth header.', 'mx.example; spf=pass dkim=pass dmarc=pass'),
            'attachment_url': make_message(INPUT_DIR / 'attachment_url.eml', 'attachment url', 'Please see https://example.org/login for details.', attachment=True),
        }
        results = {}
        with patched_external_boundaries():
            results['missing_auth'] = run_gui_case(cases['missing_auth'], runtime)
            results['forged_pass'] = run_gui_case(cases['forged_pass'], runtime)
            results['attachment_url'] = run_gui_case(cases['attachment_url'], runtime)
            results['repeat_second'] = run_gui_case(cases['missing_auth'], runtime)

            runtime_match = dict(runtime)
            runtime_match['engine_config_override'] = {'razor_command': razor_command('match'), 'razor_timeout': 1}
            results['razor_match'] = run_gui_case(cases['missing_auth'], runtime_match)

            runtime_error = dict(runtime)
            runtime_error['engine_config_override'] = {'razor_command': razor_command('error'), 'razor_timeout': 1}
            results['razor_error'] = run_gui_case(cases['missing_auth'], runtime_error)

            runtime_timeout = dict(runtime)
            runtime_timeout['engine_config_override'] = {'razor_command': razor_command('timeout'), 'razor_timeout': 1}
            results['razor_timeout'] = run_gui_case(cases['missing_auth'], runtime_timeout)
    after = {'exists': kb.exists(), 'sha256': sha256(kb)}
    repeat_dirs = [results['missing_auth']['result_dir'], results['repeat_second']['result_dir']]
    summary = {
        'knowledge_base_before': before,
        'knowledge_base_after': after,
        'knowledge_base_unchanged': before == after,
        'run_root': str(RUN_ROOT.relative_to(ROOT)),
        'inputs_dir': str(INPUT_DIR.relative_to(ROOT)),
        'results_dir': str(RESULTS_DIR.relative_to(ROOT)),
        'repeat_result_dirs_distinct': len(set(repeat_dirs)) == 2,
        'all_result_dirs_under_run_root': all((ROOT / case['result_dir']).is_relative_to(RESULTS_DIR) for case in results.values()),
        'external_boundaries_replaced': ['WHOIS lookup', 'DNS lookup/comparison', 'URL accessibility/fetch via runtime disable_network'],
        'razor_boundary': 'real RazorEngine.analyze with subprocess commands for match/miss/error/timeout',
        'cases': results,
    }
    (RUN_ROOT / 'real_analyzer_gui_results.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    (RUN_ROOT / 'README.md').write_text(
        '# Real analyzer GUI integration\n\n'
        '```cmd\n'
        'set EMAIL_DISABLE_REMOTE_AI=1&& set QT_QPA_PLATFORM=offscreen&& "C:\\Users\\berm0\\Documents\\Codex\\2026-09-11\\x20\\work\\analysis-venv\\Scripts\\python.exe" -B tests\\real_analyzer_gui_integration.py\n'
        '```\n', encoding='utf-8')
    print(json.dumps({'result': str((RUN_ROOT / 'real_analyzer_gui_results.json').relative_to(ROOT)), 'run_root': str(RUN_ROOT.relative_to(ROOT)), 'knowledge_base_unchanged': summary['knowledge_base_unchanged'], 'cases': list(results)}, ensure_ascii=False))
    if not summary['knowledge_base_unchanged'] or not summary['repeat_result_dirs_distinct'] or not summary['all_result_dirs_under_run_root']:
        raise SystemExit(1)
    expected = {
        'missing_auth': 'ok',
        'razor_match': 'ok',
        'razor_error': 'error',
        'razor_timeout': 'error',
    }
    for case, status in expected.items():
        actual = summary['cases'][case]['engine_statuses'].get('razor')
        if actual != status:
            raise SystemExit(f'Unexpected Razor status for {case}: {actual}')


if __name__ == '__main__':
    main()
