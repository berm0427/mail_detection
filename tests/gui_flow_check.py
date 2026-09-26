import json
import os
import sys
from email.message import EmailMessage
from pathlib import Path

os.environ.setdefault('EMAIL_DISABLE_REMOTE_AI', '1')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import QEventLoop, QTimer
from PyQt5.QtWidgets import QApplication

import main_gui
from main_gui import EmailAnalyzerGUI


OUT = ROOT / 'analysis_result' / 'decision-gui-flow_20260918T0115'


def make_eml(path, subject, body):
    msg = EmailMessage()
    msg['From'] = 'Flow Test <sender@example.org>'
    msg['To'] = 'user@example.net'
    msg['Subject'] = subject
    msg.set_content(body)
    path.write_bytes(msg.as_bytes())
    return path


class FakeAnalyzer:
    calls = 0

    def __init__(self, result_dir=None, attachments_dir=None, runtime_options=None):
        self.result_dir = Path(result_dir)
        self.attachments_dir = Path(attachments_dir)

    def analyze_email(self, email_path):
        FakeAnalyzer.calls += 1
        self.result_dir.mkdir(parents=True, exist_ok=True)
        self.attachments_dir.mkdir(parents=True, exist_ok=True)
        if 'fail' in Path(email_path).name:
            raise RuntimeError('synthetic analysis failure')
        result = {
            'verdict': 'inconclusive',
            'risk_score': 0,
            'risk_threshold': 70,
            'session_path': self.result_dir.name,
            'subject': Path(email_path).stem,
            'reasons': [],
            'rule_result': {
                'risk_score': 0,
                'risk_threshold': 70,
                'verdict': 'inconclusive',
                'reasons': [],
                'auth_summary': {'failures': [], 'limitations': [{'method': 'SPF', 'status': 'missing'}], 'errors': [], 'incomplete': True},
            },
            'decision': {
                'policy_version': 'evidence-review-v2',
                'verdict': 'inconclusive',
                'reasons': ['이메일 인증 정보가 부족하거나 조회 오류가 있어 인증 상태를 안전 근거로 사용할 수 없습니다.'],
            },
            'engine_results': {
                'numerical_features': {'status': 'ok', 'details': {'features': {}, 'schema_version': 1}},
                'ml_baseline': {'status': 'ok', 'score': 0.1, 'details': {'model_id': 'synthetic'}},
                'razor': {'status': 'ok', 'details': {'catalogue_match': False}},
            },
        }
        (self.result_dir / 'final_analysis_result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        return result


def wait_for_thread(window, timeout_ms=5000):
    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    if window.analysis_thread:
        window.analysis_thread.finished.connect(loop.quit)
    timer.start(timeout_ms)
    loop.exec_()
    if window.analysis_thread and window.analysis_thread.isRunning():
        raise TimeoutError('analysis thread did not finish')
    settle = QEventLoop()
    QTimer.singleShot(100, settle.quit)
    settle.exec_()
    QApplication.processEvents()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'README.md').write_text(
        '# GUI flow verification\n\n'
        'Re-run from project root with:\n\n'
        '```cmd\n'
        'set EMAIL_DISABLE_REMOTE_AI=1&& set QT_QPA_PLATFORM=offscreen&& "C:\\Users\\berm0\\Documents\\Codex\\2026-09-11\\x20\\work\\analysis-venv\\Scripts\\python.exe" -B tests\\gui_flow_check.py\n'
        '```\n', encoding='utf-8')
    ok1 = make_eml(OUT / 'ok1.eml', 'ok1', 'first synthetic GUI flow message')
    ok2 = make_eml(OUT / 'ok2.eml', 'ok2', 'second synthetic GUI flow message')
    fail = make_eml(OUT / 'fail.eml', 'fail', 'synthetic GUI flow failure')

    app = QApplication.instance() or QApplication([])
    window = EmailAnalyzerGUI()
    window.runtime_options = {'analyzer_factory': FakeAnalyzer}
    try:
        window.file_path_edit.setText(str(ok1)); window.start_analysis(); wait_for_thread(window)
        first_rows = window.engine_table.rowCount()
        first_summary = window.summary_text.toPlainText()
        first_enabled = window.analyze_button.isEnabled()
        first_status = window.status_label.text()
        assert first_rows >= 1
        assert first_enabled and first_status != '분석 중...'
        saved = list((ROOT / 'analysis_result').glob('ok1_*/final_analysis_result.json'))
        assert saved, 'first analysis did not save result'

        window.file_path_edit.setText(str(fail)); window.start_analysis(); wait_for_thread(window)
        assert window.analyze_button.isEnabled()
        assert window.status_label.text() != '분석 중...'
        assert window.engine_table.rowCount() == 0

        window.file_path_edit.setText(str(ok2)); window.start_analysis(); wait_for_thread(window)
        assert window.analyze_button.isEnabled()
        assert window.status_label.text() != '분석 중...'
        assert window.engine_table.rowCount() == first_rows
        saved2 = list((ROOT / 'analysis_result').glob('ok2_*/final_analysis_result.json'))
        assert saved2, 'second analysis did not save result'

        summary = {
            'first_rows': first_rows,
            'first_summary_length': len(first_summary),
            'first_status': first_status,
            'failure_status': '분석 실패',
            'second_rows': window.engine_table.rowCount(),
            'analyze_button_enabled': window.analyze_button.isEnabled(),
            'saved_results': [str(p.relative_to(ROOT)) for p in saved + saved2],
            'fake_analyzer_calls': FakeAnalyzer.calls,
        }
        (OUT / 'gui_flow_result.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(summary, ensure_ascii=False))
    finally:
        window.runtime_options = {}


if __name__ == '__main__':
    main()
