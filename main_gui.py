import sys
import os
import traceback
from pathlib import Path
import threading
import re
import multiprocessing

if getattr(sys, 'frozen', False):
    # Windows에서 Java 자동 찾기
    import subprocess
    try:
        result = subprocess.run(['where', 'java'], capture_output=True, text=True)
        if result.returncode == 0:
            java_path = os.path.dirname(result.stdout.strip())
            java_home = os.path.dirname(java_path)
            os.environ['JAVA_HOME'] = java_home
    except:
        # Java를 찾지 못하면 기본 경로 시도
        os.environ['JAVA_HOME'] = r'C:\Program Files\Java\jdk-17'

if __name__ == '__main__':
    multiprocessing.freeze_support()
    
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QFileDialog, QTabWidget, 
                            QTextEdit, QProgressBar, QMessageBox, QFrame, QGroupBox, 
                            QStatusBar, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QIcon

_NATIVE_ICON_HANDLES = []


# 이모티콘 설정
EMOJI = {
    "dangerous": "🚨 위험",
    "suspicious": "⚠️ 주의",
    "legitimate": "✅ 안전",
    "inconclusive": "❌ 분석 오류",
    "no_signal": "ℹ️ 탐지된 위험 신호 없음",
    "error": "❌ 오류"
}


def application_icon_path():
    """Return the bundled icon path for source and frozen executions."""
    base_dir = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    for filename in ('app_icon.ico', 'app_icon.png'):
        candidate = base_dir / 'assets' / filename
        if candidate.is_file():
            return candidate
    return None


def apply_native_windows_icon(window, icon_path):
    """Apply both Windows taskbar icon sizes to the native window handle."""
    if sys.platform != 'win32' or not icon_path or icon_path.suffix.lower() != '.ico':
        return
    try:
        import ctypes
        load_image = ctypes.windll.user32.LoadImageW
        load_image.restype = ctypes.c_void_p
        handle = load_image(None, str(icon_path), 1, 0, 0, 0x10)
        if handle:
            _NATIVE_ICON_HANDLES.append(handle)
            hwnd = int(window.winId())
            ctypes.windll.user32.SendMessageW(hwnd, 0x0080, 0, handle)
            ctypes.windll.user32.SendMessageW(hwnd, 0x0080, 1, handle)
    except (AttributeError, OSError, TypeError, ValueError):
        pass


def build_analysis_summary(result):
    """Return the compact user-facing result; diagnostics stay in other tabs."""
    verdict = result.get('verdict', 'no_signal')
    summary = f"[분석 결과]\n\n[최종 판정] {EMOJI.get(verdict, EMOJI['no_signal'])}\n"
    decision = result.get('decision') or {}
    reflected_signals = [item for item in decision.get('signals', []) if item.get('reflected')]
    if reflected_signals:
        summary += "\n[판정 근거]\n"
        for item in reflected_signals:
            summary += f" • {item.get('summary')}\n"
    else:
        summary += "\n판정에 반영된 위험 신호가 없습니다.\n"

    semantic = (result.get('engine_results') or {}).get('semantic_ml') or {}
    semantic_details = semantic.get('details') or {}
    if semantic.get('status') == 'ok' and semantic_details.get('predicted_label') == 1:
        language = semantic_details.get('source_language', 'unknown')
        input_label = f'{language} → 한국어 번역' if semantic_details.get('translation_status') == 'translated' else f'{language} 원문'
        reflected = bool((result.get('decision') or {}).get('semantic_ml_corroborated'))
        use_label = '구조 증거와 일치하여 판정 반영' if reflected else '문맥 참고 신호'
        summary += f"\n[본문 문맥 ML] 위험 문맥 {semantic.get('score', 0):.3f} · {input_label} · {use_label}\n"

    header = result.get('header') or {}
    organization_type = header.get('organization_type') or 'unknown'
    organization_subtype = header.get('organization_subtype') or 'unknown'
    if organization_type == 'unknown' and organization_subtype == 'unknown':
        organization_label = '확인되지 않음'
    elif organization_subtype in ('unknown', organization_type):
        organization_label = organization_type
    else:
        organization_label = f'{organization_type}/{organization_subtype}'
    organization_emoji = {
        'public': '🏛️',
        'financial': '🏦',
        'education': '🎓',
        'technology': '💻',
        'user': '👤',
        'unknown': 'ℹ️',
    }.get(organization_type, '🏢')
    summary += f"\n[발신자 기관 유형] {organization_emoji} {organization_label}\n"

    attachments = result.get('attachments') or []
    if attachments:
        summary += f"\n[첨부파일 검사] {len(attachments)}개\n"
        status_labels = {
            'clean': '위험 신호 없음',
            'clean_static': '정적 구조 검사 완료 · 백신 검사 미완료',
            'suspicious_structure': '의심 구조 발견',
            'threat_detected': '악성코드 탐지',
            'timeout': '검사 시간 초과',
            'error': '검사 오류',
            'disabled': '검사 비활성화',
            'unavailable': '검사 엔진 없음',
        }
        for attachment in attachments:
            scan = attachment.get('malware_scan') or {}
            status = scan.get('status', 'unavailable')
            summary += f" • {attachment.get('filename', '이름 없음')}: {status_labels.get(status, status)}\n"
            if scan.get('threat_name'):
                summary += f"   탐지명: {scan['threat_name']}\n"
            if scan.get('static_findings'):
                summary += f"   구조 근거: {', '.join(scan['static_findings'])}\n"
    return summary + f"\n세션 경로: analysis_result/{result['session_path']}"

class LogSignals(QObject):
    """로그 이벤트 신호를 전달하는 클래스"""
    log_message = pyqtSignal(str)
    summary_message = pyqtSignal(str)
    analysis_complete = pyqtSignal(bool)
    result_ready = pyqtSignal(dict)

class AnalysisThread(QThread):
    """이메일 분석을 위한 별도 스레드"""
    def __init__(self, email_path, base_dir, signals, runtime_options=None):
        super().__init__()
        self.email_path = email_path
        self.base_dir = base_dir
        self.signals = signals
        self.runtime_options = dict(runtime_options or {})
        
    def run(self):
        try:
            email_path = Path(self.email_path)
            if not email_path.exists():
                self.signals.log_message.emit(f"{EMOJI['error']} 이메일 파일을 찾을 수 없음: {email_path}")
                self.signals.analysis_complete.emit(False)
                return
            
            # 세션 ID 생성 (파일명 기반)
            session_id = f"{email_path.stem}_{os.urandom(4).hex()}"
            
            # 세션별 결과 디렉토리 생성
            result_parent = Path(self.runtime_options.get('analysis_result_root') or (self.base_dir / "analysis_result"))
            result_dir = result_parent / session_id
            os.makedirs(result_dir, exist_ok=True)
            
            # 세션별 첨부파일 디렉토리 생성
            attachments_dir = result_dir / "attachments"
            os.makedirs(attachments_dir, exist_ok=True)
            
            # 프로젝트 루트 경로를 시스템 경로에 추가
            sys.path.insert(0, str(self.base_dir))
            
            # 통합 분석기 가져오기
            from email_analyzer.integration import IntegratedAnalyzer
            analyzer_factory = self.runtime_options.get('analyzer_factory') or IntegratedAnalyzer
            
            # 로깅 리다이렉션 설정
            import logging
            logger = logging.getLogger()
            
            # 원래 핸들러 저장
            original_handlers = logger.handlers.copy()
            
            # 로그 이벤트 핸들러 클래스
            class LogHandler(logging.Handler):
                def __init__(self, signals):
                    super().__init__()
                    self.signals = signals
                
                def emit(self, record):
                    log_entry = self.format(record)
                    self.signals.log_message.emit(log_entry)
            
            # 로그 핸들러 추가
            logger.addHandler(LogHandler(self.signals))
            
            try:
                analyzer = analyzer_factory(
                    result_dir=result_dir,
                    attachments_dir=attachments_dir,
                    runtime_options=self.runtime_options,
                )
                result = analyzer.analyze_email(email_path)
                self.display_results(result)
                self.signals.analysis_complete.emit(result.get('verdict') != 'error')
            finally:
                logger.handlers = original_handlers

        except Exception as e:
            error_msg = f"\n{EMOJI['error']} 처리 중 오류 발생\n"
            error_msg += "="*50 + "\n"
            
            # 오류 유형별 처리
            if isinstance(e, FileNotFoundError):
                error_msg += "파일 시스템 오류:\n"
                error_msg += f" - {str(e)}\n"
            else:
                error_msg += "시스템 오류:\n"
                error_msg += f" - {type(e).__name__}: {str(e)}\n"
            
            error_msg += "\n상세 오류 추적:\n"
            error_msg += traceback.format_exc()
            
            self.signals.log_message.emit(error_msg)
            self.signals.summary_message.emit(f"{EMOJI['error']} 분석 중 오류가 발생했습니다.\n\n{str(e)}")
            self.signals.analysis_complete.emit(False)
            
    def display_results(self, result):
        self.signals.result_ready.emit(result)
        if result.get('verdict') == 'error':
            self.signals.summary_message.emit('분석 실패 · 판정 불가\n' + str(result.get('error', '상세 로그를 확인하세요.')))
            return
        # 필요한 모듈 import
        import re
        from pathlib import Path
        
        # 요약 탭에는 최종 판정에 실제 반영된 근거만 표시합니다.
        # 전체 DNS, 인증 관측값과 엔진 진단은 상세 로그/엔진별 근거 탭에 남습니다.
        summary = build_analysis_summary(result)
        
        # 요약 텍스트 업데이트
        self.signals.summary_message.emit(summary)


class EmailAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.base_dir = Path(__file__).parent
        self.runtime_options = {}
        
        self.setup_ui()
        
        # 분석 스레드 신호
        self.signals = LogSignals()
        self.signals.log_message.connect(self.update_log)
        self.signals.summary_message.connect(self.update_summary)
        self.signals.analysis_complete.connect(self.analysis_finished)
        self.signals.result_ready.connect(self.update_engine_results)
        
        # 분석 스레드
        self.analysis_thread = None
        
    def setup_ui(self):
        self.setWindowTitle("이메일 분석 시스템")
        icon_path = application_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(str(icon_path)))
        self.setGeometry(100, 100, 900, 700)
        self.setMinimumSize(700, 600)
        
        # 메인 위젯 및 레이아웃
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        self.setCentralWidget(central_widget)
        
        # 파일 선택 그룹 박스
        file_group = QGroupBox("이메일 파일 선택")
        file_layout = QHBoxLayout()
        file_group.setLayout(file_layout)
        
        self.file_path_edit = QLineEdit()
        browse_button = QPushButton("파일 찾기")
        analyze_button = QPushButton("분석 시작")
        self.analyze_button = analyze_button
        
        browse_button.clicked.connect(self.browse_file)
        analyze_button.clicked.connect(self.start_analysis)
        
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(analyze_button)
        
        # 도구 프레임
        tools_layout = QHBoxLayout()
        result_folder_button = QPushButton("결과 폴더 열기")
        
        result_folder_button.clicked.connect(self.open_result_folder)
        
        tools_layout.addWidget(result_folder_button)
        tools_layout.addStretch(1)
        
        # 탭 위젯
        self.tab_widget = QTabWidget()
        
        # 분석 요약 탭
        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QApplication.font("Monospace"))
        summary_layout.addWidget(self.summary_text)
        
        # 상세 로그 탭
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QApplication.font("Monospace"))
        log_layout.addWidget(self.log_text)
        
        # 탭 추가
        self.tab_widget.addTab(summary_tab, "분석 요약")
        self.tab_widget.addTab(log_tab, "상세 로그")
        
        evidence_tab = QWidget()
        evidence_layout = QVBoxLayout(evidence_tab)
        self.engine_table = QTableWidget(0, 4)
        self.engine_table.setHorizontalHeaderLabels(['분석 항목', '실행 상태', '결과', '판단 근거'])
        self.engine_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.engine_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.engine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.engine_table.setWordWrap(True)
        evidence_layout.addWidget(self.engine_table)
        self.decision_detail = QTextEdit()
        self.decision_detail.setReadOnly(True)
        self.decision_detail.setMaximumHeight(130)
        evidence_layout.addWidget(self.decision_detail)
        self.tab_widget.addTab(evidence_tab, '엔진별 근거')

        # 상태 바 및 프로그레스 바
        status_layout = QHBoxLayout()
        self.status_label = QLabel("준비됨")
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        
        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.progress_bar)
        
        # 메인 레이아웃에 위젯 추가
        main_layout.addWidget(file_group)
        main_layout.addLayout(tools_layout)
        main_layout.addWidget(self.tab_widget, 1)
        main_layout.addLayout(status_layout)
        
        # 상태 바 설정
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("준비됨")
    
    def browse_file(self):
        """파일 탐색기 열기"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, 
            "분석할 이메일 파일 선택", 
            "", 
            "이메일 파일 (*.eml);;모든 파일 (*.*)"
        )
        if filepath:
            self.file_path_edit.setText(filepath)
    
    def start_analysis(self):
        """이메일 분석 시작"""
        if self.analysis_thread and self.analysis_thread.isRunning():
            return
        filepath = self.file_path_edit.text()
        if not filepath:
            QMessageBox.warning(self, "경고", "이메일 파일을 선택해주세요.")
            return
        
        # 텍스트 영역 초기화
        self.clear_text_areas()

        # 분석 모듈을 메인 스레드에서 먼저 로드해 GUI 작업 스레드의 첫
        # import 비용과 오류 보고 지연을 줄인다.
        if not self.runtime_options.get('analyzer_factory'):
            import email_analyzer.integration  # noqa: F401
        
        # 상태 업데이트
        self.status_label.setText("분석 중...")
        self.statusBar.showMessage("분석 중...")
        self.progress_bar.setRange(0, 0)  # 무한 진행 모드
        
        # 분석 스레드 시작
        self.analysis_thread = AnalysisThread(
            filepath, 
            self.base_dir, 
            self.signals,
            runtime_options=self.runtime_options,
        )
        self.analyze_button.setEnabled(False)
        self.analysis_thread.finished.connect(lambda: self.analyze_button.setEnabled(True))
        self.analysis_thread.start()
    
    def analysis_finished(self, success):
        """분석 완료 시 호출되는 슬롯"""
        self.progress_bar.setRange(0, 100)  # 진행 모드 종료
        self.progress_bar.setValue(100)
        
        if success:
            self.status_label.setText("분석 완료")
            self.statusBar.showMessage("분석 완료")
        else:
            self.status_label.setText("분석 실패")
            self.statusBar.showMessage("분석 실패")
    
    def update_engine_results(self, result):
        from email_analyzer.engine_view import engine_rows, decision_text
        rows = engine_rows(result)
        self.engine_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.engine_table.setItem(row, column, item)
        self.engine_table.resizeRowsToContents()
        for row in range(len(rows)):
            self.engine_table.setRowHeight(row, min(150, self.engine_table.rowHeight(row)))
        self.decision_detail.setPlainText(decision_text(result))

    def update_log(self, text):
        """로그 텍스트 업데이트"""
        self.log_text.append(text)
        self.log_text.ensureCursorVisible()
    
    def update_summary(self, text):
        """요약 텍스트 업데이트"""
        self.summary_text.clear()
        self.summary_text.setPlainText(text)
        self.summary_text.ensureCursorVisible()
    
    def clear_text_areas(self):
        """텍스트 영역 초기화"""
        self.summary_text.clear()
        self.log_text.clear()
        self.engine_table.setRowCount(0)
        self.decision_detail.clear()
    
    def open_result_folder(self):
        """결과 폴더 열기"""
        results_dir = self.base_dir / "analysis_result"
        if not results_dir.exists():
            os.makedirs(results_dir)
        
        try:
            import subprocess
            if sys.platform == 'win32':
                subprocess.Popen(['explorer', str(results_dir)])
            elif sys.platform == 'darwin':  # macOS
                subprocess.Popen(['open', str(results_dir)])
            else:  # Linux
                subprocess.Popen(['xdg-open', str(results_dir)])
        except Exception as e:
            QMessageBox.critical(self, "오류", f"결과 폴더 열기 실패: {str(e)}")
    
    def closeEvent(self, event):
        """프로그램 종료 시 처리"""
        # 스레드가 실행 중이면 종료 처리
        if self.analysis_thread and self.analysis_thread.isRunning():
            reply = QMessageBox.question(
                self, 
                '확인', 
                "분석이 진행 중입니다. 정말 종료하시겠습니까?",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.analysis_thread.terminate()
                self.analysis_thread.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('DISE.EmailAnalyzer.2026')
        except (AttributeError, OSError):
            pass

    app = QApplication(sys.argv)
    app.setApplicationName('DISE 이메일 분석 시스템')
    app.setOrganizationName('DISE')
    icon_path = application_icon_path()
    if icon_path:
        app.setWindowIcon(QIcon(str(icon_path)))
    
    # 애플리케이션 폰트 설정
    font = app.font()
    font.setFamily('Malgun Gothic')
    font.setPointSize(9)
    app.setFont(font)
    
    # 모노스페이스 폰트 등록
    mono_font = app.font()
    mono_font.setFamily('Consolas')
    mono_font.setPointSize(9)
    app.setFont(mono_font, "Monospace")
    
    # 스타일 설정
    app.setStyle('Fusion')
    
    window = EmailAnalyzerGUI()
    window.show()
    apply_native_windows_icon(window, icon_path)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
