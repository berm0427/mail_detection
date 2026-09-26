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



# 이모티콘 설정
EMOJI = {
    "dangerous": "🚨 위험",
    "suspicious": "⚠️ 주의",
    "legitimate": "✅ 안전",
    "inconclusive": "❌ 분석 오류",
    "no_signal": "ℹ️ 탐지된 위험 신호 없음",
    "error": "❌ 오류"
}

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
        
        # 요약 결과 생성
        summary = "[분석 결과]\n\n"
        risk_score = result.get('risk_score', 0)
        risk_threshold = result.get('risk_threshold', 70)
        header = result.get('header') or {}
        body = result.get('body') or {'total_matches': 0, 'categories': {}}
        
        # 도메인 평판 조정 정보 확인
        domain_reputation_adjusted = result.get('domain_reputation_adjusted', False)
        domain_age_days = result.get('domain_age_days', None)
        
        # 도메인 나이 정보가 없는 경우 헤더에서 가져오기
        if not domain_age_days and header.get('details') and header['details'].get('domain_info'):
            domain_info = header['details']['domain_info']
            domain_age_days = domain_info.get('domain_age_days')
        
       
        # 판정 결과 확인 (analyze_email 함수 결과 그대로 사용)
        verdict = result.get('verdict', 'legitimate')
        
        # 판정 결과 표시
        summary += f"[최종 판정] {EMOJI.get(verdict, EMOJI['legitimate'])}\n"
        if verdict == 'dangerous':
            summary += " - 이 이메일은 높은 위험성으로 판단됩니다. 즉시 삭제를 권장합니다.\n"
        elif verdict == 'suspicious':
            summary += " - URL·본문·HTML·인증·첨부파일 검사에서 위험 근거가 발견되었습니다. 아래 근거를 확인하세요.\n"
        elif verdict == 'no_signal':
            summary += " - 검사한 규칙과 HTML에서 위험 신호가 발견되지 않았습니다.\n"
        elif verdict == 'inconclusive':
            from email_analyzer.engine_view import inconclusive_explanation
            summary += " - 분석 오류: " + inconclusive_explanation(result) + "\n"
        else:
            summary += " - 현재 분석에서 위험 신호가 낮게 나타났습니다.\n"
        
        from email_analyzer.engine_view import decision_text
        summary += '\n[판정 근거]\n' + decision_text(result) + '\n'
        decision = result.get('decision') or {}
        reflected_signals = [item for item in decision.get('signals', []) if item.get('reflected')]
        advisory_signals = [item for item in decision.get('signals', []) if not item.get('reflected')]
        summary += f"\n[통합 판정 신호] 판정 반영 {len(reflected_signals)}건"
        if advisory_signals:
            summary += f" · 참고 {len(advisory_signals)}건"
        summary += "\n"
        for item in reflected_signals:
            summary += f" • [{item.get('source')}] {item.get('summary')}\n"
        for item in advisory_signals:
            summary += f" ℹ️ [참고·미반영/{item.get('source')}] {item.get('summary')}\n"
        if not decision.get('signals'):
            summary += " • 판정에 반영된 위험 신호 없음\n"

        # 도메인 평판 정보 추가
        if header.get('sender_domain'):
            sender_domain = header.get('sender_domain', '알 수 없음')
            
            summary += f"\n[도메인 등록·관측 정보] {sender_domain}\n"
        
        # 도메인 나이 정보 가져오기
        creation_date = None
        if header.get('details') and header['details'].get('domain_info'):
            domain_info = header['details']['domain_info']
            # domain_age_days는 이미 위에서 가져옴
            creation_date = domain_info.get('creation_date')
        
        # 도메인 평판 상태 확인
        domain_reputation = header.get('domain_reputation', 'unknown')
        
        # 도메인 나이에 따른 평판 표시 - 재조정 여부와 실제 평판 상태 모두 고려
        if domain_reputation_adjusted:
            # 조정된 경우 - 나이에 따라 신뢰 표시
            summary += f" ℹ️ 도메인 등록 정보: {domain_age_days}일 전에 등록된 도메인입니다. 등록 기간은 참고 정보로 표시하며 판정 점수에서 제외합니다.\n"
        elif domain_reputation == "suspicious":
            # 의심스러운 도메인 (조정되지 않음)
            if domain_age_days:
                summary += f" ⚠️ 의심스러운 도메인: {domain_age_days}일 전에 등록되었으나 도메인 형식으로 인해 의심스럽습니다.\n"
            else:
                summary += f" ⚠️ 의심스러운 도메인: 평판 분석에서 의심 요소가 감지되었습니다.\n"
        elif domain_reputation == "established":
            # 확립된 도메인
            if domain_age_days:
                summary += f" ℹ️ 도메인 등록 정보: {domain_age_days}일 전에 등록된 도메인입니다. 등록 기간은 참고 정보로 표시하며 판정 점수에서 제외합니다.\n"
            else:
                summary += f" ℹ️ 도메인 등록 정보: 오랜 기간 등록되어 있는 도메인입니다. 등록 기간은 참고 정보로 표시하며 판정 점수에서 제외합니다.\n"
        else:
            # 기타 상태
            if domain_age_days:
                if domain_age_days < 30:
                    summary += f" ⚠️ 최근({domain_age_days}일 전)에 생성된 도메인입니다.\n"
                else:
                    summary += f" ℹ️ {domain_age_days}일 전에 등록된 도메인입니다. 등록 기간은 참고 정보로 표시하며 판정 점수에서 제외합니다.\n"
            elif creation_date and str(creation_date).lower() not in ("unknown", "none", "null"):
                summary += f" ℹ️ {creation_date}에 등록된 도메인입니다.\n"
            else:
                summary += f" ℹ️ 도메인 정보를 확인할 수 없습니다.\n"
                
        # 첨부 파일 정보
        if result.get('attachments'):
            summary += f"\n[첨부 파일: {len(result['attachments'])}개]\n"
            has_unsafe_attachment = False
            
            for i, att in enumerate(result['attachments'], 1):
                is_safe = att.get('safe')
                status_emoji = "ℹ️" if is_safe is None else "✅" if is_safe else "⚠️"
                
                # 안전하지 않은 첨부 파일이 있는지 확인
                if is_safe is False:
                    has_unsafe_attachment = True
                    
                # 파일 크기 형식화 (KB/MB 단위로)
                size = att.get('size', 0)
                if size > 1048576:  # 1MB
                    formatted_size = f"{size/1048576:.2f} MB"
                elif size > 1024:  # 1KB
                    formatted_size = f"{size/1024:.1f} KB"
                else:
                    formatted_size = f"{size} 바이트"
                    
                # 파일 유형에 따른 아이콘 추가
                file_type = att.get('type', '').lower()
                file_icon = "📄"  # 기본 문서
                if 'image' in file_type:
                    file_icon = "🖼️"
                elif 'pdf' in file_type:
                    file_icon = "📑"
                elif 'excel' in file_type or 'spreadsheet' in file_type:
                    file_icon = "📊"
                elif 'word' in file_type or 'document' in file_type:
                    file_icon = "📝"
                elif 'zip' in file_type or 'compressed' in file_type:
                    file_icon = "🗜️"
                elif 'executable' in file_type or 'application' in file_type:
                    file_icon = "⚙️"
                    
                summary += f" {i}. {status_emoji} {file_icon} {att['filename']} ({formatted_size})\n"
                scan = att.get('malware_scan') or {}
                scan_status = scan.get('status')
                if scan_status:
                    labels = {
                        'clean': '자체 정적 검사 및 백신 검사에서 위험 신호 없음',
                        'clean_static': '자체 정적 검사에서 위험 신호 없음',
                        'suspicious_structure': '자체 정적 검사에서 의심 구조 발견',
                        'threat_detected': '악성코드 탐지', 'alert': '백신 경고',
                        'timeout': '검사 시간 초과', 'error': '백신 검사 오류',
                        'disabled': '검사 비활성화', 'unavailable': '검사 엔진 없음',
                    }
                    summary += f"    악성코드 검사: {labels.get(scan_status, scan_status)}\n"
                    if scan.get('static_findings'):
                        summary += f"    탐지 근거: {', '.join(scan['static_findings'])}\n"
                if att.get('reason'):
                    reason_labels = {
                        'internal_static_scan_clean': '자체 정적 검사에서 위험 구조 없음',
                        'internal_static_scan_clean; defender_scan_unavailable_or_failed': '자체 정적 검사에서 위험 구조 없음 · Defender 검사는 완료되지 않음',
                        'internal_static_scan_clean; defender_product_disabled': '자체 정적 검사에서 위험 구조 없음 · 다른 백신 사용으로 Defender가 비활성화됨',
                        'internal_static_scan_clean; defender_scan_failed': '자체 정적 검사에서 위험 구조 없음 · Defender 검사 시작 실패',
                        'Defender reported a threat': 'Defender가 위협을 탐지함',
                        'ClamAV reported a threat': 'ClamAV가 위협을 탐지함',
                        'ClamAV scan completed; Defender unavailable': 'ClamAV 검사 완료 · Defender 사용 불가',
                        'ClamAV scan completed; Defender timed out': 'ClamAV 검사 완료 · Defender 시간 초과',
                        'ClamAV scan completed; Defender failed': 'ClamAV 검사 완료 · Defender 실행 실패',
                        'ClamAV scan completed; defender_product_disabled': 'ClamAV 검사 완료 · 다른 백신 사용으로 Defender 비활성화',
                        'attachment_missing': '저장된 첨부파일을 찾을 수 없음',
                    }
                    reason_text = reason_labels.get(att['reason'], att['reason'])
                    summary += f"    - 검사 근거: {reason_text}\n"
                if scan.get('external_error_code'):
                    summary += f"    - 외부 백신 오류 코드: {scan['external_error_code']}\n"
                clamav = scan.get('clamav') or {}
                clamav_labels = {'clean':'위험 신호 없음','threat_detected':'위협 탐지',
                                  'unavailable':'설치되지 않음','error':'검사 오류','timeout':'검사 시간 초과'}
                if clamav:
                    summary += f"    - ClamAV: {clamav_labels.get(clamav.get('status'),clamav.get('status'))}\n"
                    if clamav.get('threat_name'):
                        summary += f"      탐지명: {clamav['threat_name']}\n"
            
            # 첨부 파일 안전성에 대한 추가 설명
            if has_unsafe_attachment:
                summary += " ⚠️ 첨부파일 위험 신호가 발견되었습니다. 파일별 검사 결과를 확인하세요.\n"
            else:
                summary += " 첨부파일 검사 상태는 파일별 결과에 표시합니다.\n"

        # 기관 유형 정보 출력
        if header.get('organization_type'):
            org_type = header['organization_type']
            org_subtype = header.get('organization_subtype', 'unknown')
            
            # 기관 유형별 이모지 추가
            org_emoji = "🏢"
            if org_type == "public":
                org_emoji = "🏛️"
            elif org_type == "financial":
                org_emoji = "🏦"
            elif org_type == "education":
                org_emoji = "🎓"
            elif org_type == "technology":
                org_emoji = "💻"
            elif org_type == "user":
                org_emoji = "👤"
            
            summary += f"\n[발신자 기관 유형] {org_emoji} {org_type}/{org_subtype}\n"
            
            # 사칭 가능성 경고 추가
            if header.get('impersonation') == 'suspected':
                summary += f" ⚠️ 사칭 가능성 있음: {header.get('impersonation_reason', '')}\n"
        
        # 헤더 검증 정보 요약
        if header:
            summary += "\n[헤더 검증 결과]\n"
            header_checks = {
                'spf_check': 'SPF 검증',
                'dkim_check': 'DKIM 검증',
                'dmarc_check': 'DMARC 검증',
                'dnssec_status': 'DNSSEC'
            }
            
            for check, desc in header_checks.items():
                if check in header:
                    status = header[check]
                    if check == 'dnssec_status':
                        status_emoji = "✅" if status == "signed" else "ℹ️"
                    else:
                        from email_analyzer.legacy_rules import classify_auth_status
                        category = classify_auth_status(status)
                        status_emoji = {"pass": "✅", "fail": "❌", "error": "⚠️", "missing": "ℹ️"}[category]
                        if category == "missing":
                            status = {'spf_check':'판정 제외 · 송신 IP 또는 SPF 판정 자료 없음', 'dkim_check':'판정 제외 · 검증 가능한 DKIM 서명 자료 없음', 'dmarc_check':'판정 제외 · SPF/DKIM 정렬 결과 없음'}.get(check,'판정 제외 · 원본 자료 없음')
                    summary += f" {status_emoji} {desc}: {status}\n"

        from email_analyzer.legacy_rules import auth_observation_lines
        for line in auth_observation_lines(header.get('auth_evidence') or {}):
            summary += " ℹ️ " + line + "\n"

        dns_queries = (header.get('details') or {}).get('dns_queries') or []
        if dns_queries:
            summary += "\n[DNS 조회 상태]\n"
            dns_labels = {'ok': '조회 성공', 'nxdomain': '도메인 없음', 'no_record': '해당 레코드 없음', 'timeout': '조회 시간 초과', 'error': '조회 오류', 'reserved_test_domain': '예약된 테스트 도메인 · 공개 조회 제외'}
            for query in dns_queries:
                summary += f" ℹ️ {query['domain']} {query['type']}: {dns_labels.get(query['status'], query['status'])}\n"
            summary += " DNS 레코드 조회 성공은 메일 발신자 인증 성공과 다릅니다.\n"

        # 위험 요소 및 조정 설명 - 분석기에서 제공한 이유 목록 사용
        summary += "\n[위험 요소 분석]\n"
        
        # 분석기에서 제공한 이유 목록 사용 (중복 방지)
        if 'reasons' in result:
            for reason in result['reasons']:
                # 도메인 평판 관련 이유는 평판이 조정된 경우 조정 메시지로 대체
                if "도메인 평판 의심" in reason and not "취소됨" in reason and domain_reputation_adjusted:
                    domain_reputation_score = 25
                    summary += f" • <취소됨> 도메인 평판 의심: +{domain_reputation_score} (도메인 나이 {domain_age_days}일로 인해 차감)\n"
                else:
                    summary += f" • {reason}\n"
        
        # 위험도 점수
        summary += f"\n[기존 규칙 진단 점수] {risk_score}/100 · 규칙 위험 기준 {risk_threshold}\n"
        summary += "이 숫자는 규칙 엔진의 진단값이며 ML 확률·도메인·HTML 결과를 더한 최종 위험도가 아닙니다. 최종 결과는 위 통합 판정 신호로 결정합니다.\n"
        
        # 위험도에 따른 시각적 표현
        if verdict == 'dangerous':
            summary += "🔴 높은 위험 - 즉시 확인이 필요합니다.\n"
        elif verdict == 'suspicious':
            summary += "🟠 중간 위험 - 주의가 필요합니다.\n"
        elif verdict == 'inconclusive':
            summary += "❌ 분석 오류 - 상세 로그에서 실패 항목을 확인하세요.\n"
        elif verdict == 'no_signal':
            summary += "ℹ️ 최종 판정에 반영된 위험 신호 0건\n"
        else:  # legitimate
            summary += "🟢 안전 - 위험 요소가 발견되지 않았습니다.\n"
            
        # AI 분석 결과 표시
        if 'ai_analysis' in result:
            ai_result = result['ai_analysis']
            ai_verdict = ai_result.get('verdict', '알 수 없음')
            
            # AI 판정 이모지 결정
            ai_emoji = "🤖"
            if ai_verdict == "안전":
                ai_emoji = "🟢"
            elif ai_verdict == "의심":
                ai_emoji = "🟠"
            elif ai_verdict == "위험":
                ai_emoji = "🔴"
            
            summary += f"\n\n[AI 분석 결과] {ai_emoji} {ai_verdict}\n"
            
            # AI 위험도 점수
            ai_risk_score = ai_result.get('risk_score', 0)
            summary += f"AI 위험도 평가: {ai_risk_score}/100\n"
            
            # 위험도 조정 정보
            if result.get('ai_adjusted'):
                summary += f" ℹ️ AI 분석 결과가 최종 위험도 점수에 반영되었습니다.\n"
            
            # 의심스러운 요소
            if 'suspicious_elements' in ai_result and ai_result['suspicious_elements']:
                summary += "\n의심스러운 요소:\n"
                for element in ai_result['suspicious_elements']:
                    summary += f" • {element}\n"
            
            # AI 설명
            if 'explanation' in ai_result and ai_result['explanation']:
                summary += f"\n분석 설명:\n{ai_result['explanation']}\n"
            
            # AI 권장사항
            if 'recommendation' in ai_result and ai_result['recommendation']:
                summary += f"\n권장 조치:\n{ai_result['recommendation']}\n"
        
        summary += f"\n세션 경로: analysis_result/{result['session_path']}"
        
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
    
    app = QApplication(sys.argv)
    
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
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
