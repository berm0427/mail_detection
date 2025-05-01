import sys
import json
import os
import traceback
from pathlib import Path
import threading
import re
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QFileDialog, QTabWidget, 
                            QTextEdit, QProgressBar, QMessageBox, QFrame, QGroupBox, 
                            QStatusBar, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject

# 이모티콘 설정
EMOJI = {
    "dangerous": "🚨 위험",
    "suspicious": "⚠️ 주의",
    "legitimate": "✅ 안전",
    "error": "❌ 오류"
}

class LogSignals(QObject):
    """로그 이벤트 신호를 전달하는 클래스"""
    log_message = pyqtSignal(str)
    summary_message = pyqtSignal(str)
    analysis_complete = pyqtSignal(bool)

class AnalysisThread(QThread):
    """이메일 분석을 위한 별도 스레드"""
    def __init__(self, email_path, base_dir, keywords_dir, signals):
        super().__init__()
        self.email_path = email_path
        self.base_dir = base_dir
        self.keywords_dir = keywords_dir
        self.signals = signals
        
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
            result_dir = self.base_dir / "analysis_result" / session_id
            os.makedirs(result_dir, exist_ok=True)
            
            # 세션별 첨부파일 디렉토리 생성
            attachments_dir = result_dir / "attachments"
            os.makedirs(attachments_dir, exist_ok=True)
            
            # 프로젝트 루트 경로를 시스템 경로에 추가
            sys.path.insert(0, str(self.base_dir))
            
            # 통합 분석기 가져오기
            from email_analyzer.integration import IntegratedAnalyzer
            
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
            
            # 분석기 초기화
            analyzer = IntegratedAnalyzer(
                keywords_dir=self.keywords_dir,
                result_dir=result_dir,
                attachments_dir=attachments_dir
            )
            
            # 이메일 분석 실행
            result = analyzer.analyze_email(email_path)
            
            # 로깅 핸들러 복원
            logger.handlers = original_handlers
            
            # 결과 처리 및 표시
            self.display_results(result)
            
            self.signals.analysis_complete.emit(True)
            
        except Exception as e:
            error_msg = f"\n{EMOJI['error']} 처리 중 오류 발생\n"
            error_msg += "="*50 + "\n"
            
            # 오류 유형별 처리
            if isinstance(e, FileNotFoundError):
                error_msg += "파일 시스템 오류:\n"
                error_msg += f" - {str(e)}\n"
            elif isinstance(e, json.JSONDecodeError):
                error_msg += "키워드 파일 형식 오류:\n"
                error_msg += f" - {e.doc}\n"
                error_msg += f" - 위치: {e.pos}, 줄: {e.lineno}, 열: {e.colno}\n"
                error_msg += f" - 수정 방법: JSON 형식을 확인하세요. 일반적으로 따옴표, 쉼표, 괄호 등의 오류입니다.\n"
            else:
                error_msg += "시스템 오류:\n"
                error_msg += f" - {type(e).__name__}: {str(e)}\n"
            
            error_msg += "\n상세 오류 추적:\n"
            error_msg += traceback.format_exc()
            
            self.signals.log_message.emit(error_msg)
            self.signals.summary_message.emit(f"{EMOJI['error']} 분석 중 오류가 발생했습니다.\n\n{str(e)}")
            self.signals.analysis_complete.emit(False)
            
    def display_results(self, result):
        # 필요한 모듈 import
        import re
        from pathlib import Path
        
        # 요약 결과 생성
        summary = "[분석 결과]\n\n"
        risk_score = result.get('risk_score', 0)
        risk_threshold = result.get('risk_threshold', 70)
        
        # 도메인 평판 조정 정보 확인
        domain_reputation_adjusted = result.get('domain_reputation_adjusted', False)
        domain_age_days = result.get('domain_age_days', None)
        
        # 도메인 나이 정보가 없는 경우 헤더에서 가져오기
        if not domain_age_days and result.get('header') and result['header'].get('details') and result['header']['details'].get('domain_info'):
            domain_info = result['header']['details']['domain_info']
            domain_age_days = domain_info.get('domain_age_days')
        
       
        # 판정 결과 확인 (analyze_email 함수 결과 그대로 사용)
        verdict = result.get('verdict', 'legitimate')
        
        # 판정 결과 표시
        summary += f"[최종 판정] {EMOJI.get(verdict, EMOJI['legitimate'])}\n"
        if verdict == 'dangerous':
            summary += " - 이 이메일은 높은 위험성으로 판단됩니다. 즉시 삭제를 권장합니다.\n"
        elif verdict == 'suspicious':
            summary += " - 이 이메일은 의심스러운 내용을 포함하고 있습니다. 주의가 필요합니다.\n"
        else:
            summary += " - 이 이메일은 안전한 것으로 판단됩니다.\n"
        
        # 제목 위험 키워드 정보 추가 - 로그 및 간접 추출
        subject_keywords_count = 0
        found_keywords = []
        subject = ""
        
        # 제목 가져오기
        if 'subject' in result:
            subject = result['subject']
        elif 'metadata' in result and 'Subject' in result['metadata']:
            subject = result['metadata']['Subject']
        
        # 제목 키워드 수 파악 - result에서 직접 가져오기
        for reason in result.get('reasons', []):
            if "제목에 의심스러운 키워드" in reason:
                match = re.search(r'제목에 의심스러운 키워드 (\d+)개', reason)
                if match:
                    subject_keywords_count = int(match.group(1))
                    break
        
        # integration.py의 subject_suspicious_patterns 가져오기
        try:
            # 프로젝트 경로 구하기
            project_root = self.base_dir
            integration_path = project_root / "email_analyzer" / "integration.py"
            
            if integration_path.exists():
                with open(integration_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # subject_suspicious_patterns 변수 찾기
                pattern = r"subject_suspicious_patterns\s*=\s*\[(.*?)\]"
                matches = re.search(pattern, content, re.DOTALL)
                
                if matches:
                    patterns_block = matches.group(1)
                    
                    # 각 패턴에서 키워드 추출
                    keywords_from_patterns = []
                    for line in patterns_block.split('\n'):
                        line = line.strip()
                        if line.startswith('r\'') or line.startswith('r"'):
                            # 정규식 패턴에서 키워드 추출
                            pattern_match = re.search(r'r[\'"](.+?)[\'"]', line)
                            if pattern_match:
                                pattern = pattern_match.group(1)
                                # '|' 구분자로 나눠진 키워드 추출
                                keywords = pattern.split('|')
                                for keyword in keywords:
                                    # 정규식 이스케이프 문자 제거
                                    keyword = re.sub(r'\\', '', keyword)
                                    if keyword and keyword not in keywords_from_patterns:
                                        keywords_from_patterns.append(keyword)
                    
                    # 제목에서 키워드 찾기
                    if subject:
                        for keyword in keywords_from_patterns:
                            if keyword in subject and keyword not in found_keywords:
                                found_keywords.append(keyword)
                                if len(found_keywords) >= subject_keywords_count:
                                    break
        except Exception as e:
            self.signals.log_message.emit(f"subject_suspicious_patterns 패턴 추출 오류: {e}")
        
        # 키워드 정보가 있으면 표시
        if subject_keywords_count > 0:
            summary += f"\n[제목 위험 키워드: {subject_keywords_count}개 발견]\n"
            if found_keywords:
                keywords_str = ', '.join(f'"{k}"' for k in found_keywords)
                summary += f" - 위험 키워드: {keywords_str}\n"
            else:
                summary += f" - 위험 키워드가 발견되었으나 상세 내용을 추출할 수 없습니다.\n"
        
        # 도메인 평판 정보 추가
        if result.get('header') and result['header'].get('sender_domain'):
            sender_domain = result['header'].get('sender_domain', '알 수 없음')
            
            summary += f"\n[도메인 평판] {sender_domain}\n"
        
        # 도메인 나이 정보 가져오기
        creation_date = None
        if result['header'].get('details') and result['header']['details'].get('domain_info'):
            domain_info = result['header']['details']['domain_info']
            # domain_age_days는 이미 위에서 가져옴
            creation_date = domain_info.get('creation_date')
        
        # 도메인 평판 상태 확인
        domain_reputation = result['header'].get('domain_reputation', 'unknown')
        
        # 도메인 나이에 따른 평판 표시 - 재조정 여부와 실제 평판 상태 모두 고려
        if domain_reputation_adjusted:
            # 조정된 경우 - 나이에 따라 신뢰 표시
            summary += f" ✅ 신뢰할 수 있는 도메인: {domain_age_days}일 전에 등록된 도메인입니다.\n"
        elif domain_reputation == "suspicious":
            # 의심스러운 도메인 (조정되지 않음)
            if domain_age_days:
                summary += f" ⚠️ 의심스러운 도메인: {domain_age_days}일 전에 등록되었으나 도메인 형식으로 인해 의심스럽습니다.\n"
            else:
                summary += f" ⚠️ 의심스러운 도메인: 평판 분석에서 의심 요소가 감지되었습니다.\n"
        elif domain_reputation == "established":
            # 확립된 도메인
            if domain_age_days:
                summary += f" ✅ 신뢰할 수 있는 도메인: {domain_age_days}일 전에 등록된 도메인입니다.\n"
            else:
                summary += f" ✅ 신뢰할 수 있는 도메인: 오랜 기간 등록되어 있는 도메인입니다.\n"
        else:
            # 기타 상태
            if domain_age_days:
                if domain_age_days < 30:
                    summary += f" ⚠️ 최근({domain_age_days}일 전)에 생성된 도메인입니다.\n"
                else:
                    summary += f" ℹ️ {domain_age_days}일 전에 등록된 도메인입니다.\n"
            elif creation_date and creation_date != "Unknown":
                summary += f" ℹ️ {creation_date}에 등록된 도메인입니다.\n"
            else:
                summary += f" ℹ️ 도메인 정보를 확인할 수 없습니다.\n"
                
        # 본문 분석 요약
        if result['body']['total_matches'] > 0:
            summary += f"\n[본문 위험 패턴: {result['body']['total_matches']}개 발견]\n"
            for category, info in result['body']['categories'].items():
                if 'examples' in info:
                    examples = ', '.join(f'"{ex}"' for ex in info['examples'][:3])
                    summary += f" - {category}: {info['count']}건 (발견: {examples})\n"
                else:
                    summary += f" - {category}: {info['count']}건\n"
        
        # 첨부 파일 정보
        if result.get('attachments'):
            summary += f"\n[첨부 파일: {len(result['attachments'])}개]\n"
            has_unsafe_attachment = False
            
            for i, att in enumerate(result['attachments'], 1):
                is_safe = att.get('safe', True)
                status_emoji = "✅" if is_safe else "⚠️"
                
                # 안전하지 않은 첨부 파일이 있는지 확인
                if not is_safe:
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
                if att.get('reason'):
                    summary += f"    - 참고: {att['reason']}\n"
            
            # 첨부 파일 안전성에 대한 추가 설명
            if has_unsafe_attachment:
                summary += " ⚠️ 주의: 일부 첨부 파일이 잠재적 위험을 포함할 수 있습니다.\n"
            else:
                summary += " ✅ 모든 첨부 파일이 안전한 것으로 확인되었습니다.\n"

        # 기관 유형 정보 출력
        if result.get('header') and result['header'].get('organization_type'):
            org_type = result['header']['organization_type']
            org_subtype = result['header'].get('organization_subtype', 'unknown')
            
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
            if result['header'].get('impersonation') == 'suspected':
                summary += f" ⚠️ 사칭 가능성 있음: {result['header'].get('impersonation_reason', '')}\n"
        
        # 헤더 검증 정보 요약
        if result.get('header'):
            summary += "\n[헤더 검증 결과]\n"
            header_checks = {
                'spf_check': 'SPF 검증',
                'dkim_check': 'DKIM 검증',
                'dmarc_check': 'DMARC 검증',
                'dnssec_status': 'DNSSEC'
            }
            
            for check, desc in header_checks.items():
                if check in result['header']:
                    status = result['header'][check]
                    if check == 'dnssec_status':
                        status_emoji = "✅" if status == "signed" else "ℹ️"
                    else:
                        status_emoji = "✅" if status == "pass" or status == "match" else "⚠️" if status == "none" or status == "not_applicable" else "❌"
                    summary += f" {status_emoji} {desc}: {status}\n"

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
        summary += f"\n[위험도] {risk_score}/{risk_threshold}\n"
        
        # 위험도에 따른 시각적 표현
        if verdict == 'dangerous':
            summary += "🔴 높은 위험 - 즉시 확인이 필요합니다.\n"
        elif verdict == 'suspicious':
            summary += "🟠 중간 위험 - 주의가 필요합니다.\n"
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
        self.keywords_dir = self.base_dir / "mail_body" / "keywords"
        self.keyword_manager_path = self.base_dir / "header_keyword_add.py"
        
        # 디렉토리 존재 확인 및 생성
        os.makedirs(self.keywords_dir, exist_ok=True)
        
        # 필요한 기본 키워드 파일 생성
        self._create_default_keywords_if_needed()
        
        self.setup_ui()
        
        # 분석 스레드 신호
        self.signals = LogSignals()
        self.signals.log_message.connect(self.update_log)
        self.signals.summary_message.connect(self.update_summary)
        self.signals.analysis_complete.connect(self.analysis_finished)
        
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
        
        browse_button.clicked.connect(self.browse_file)
        analyze_button.clicked.connect(self.start_analysis)
        
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(analyze_button)
        
        # 도구 프레임
        tools_layout = QHBoxLayout()
        keyword_manager_button = QPushButton("헤더 키워드 관리 도구")
        result_folder_button = QPushButton("결과 폴더 열기")
        
        keyword_manager_button.clicked.connect(self.open_keyword_manager)
        result_folder_button.clicked.connect(self.open_result_folder)
        
        tools_layout.addWidget(keyword_manager_button)
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
        filepath = self.file_path_edit.text()
        if not filepath:
            QMessageBox.warning(self, "경고", "이메일 파일을 선택해주세요.")
            return
        
        # 텍스트 영역 초기화
        self.clear_text_areas()
        
        # 상태 업데이트
        self.status_label.setText("분석 중...")
        self.statusBar.showMessage("분석 중...")
        self.progress_bar.setRange(0, 0)  # 무한 진행 모드
        
        # 분석 스레드 시작
        self.analysis_thread = AnalysisThread(
            filepath, 
            self.base_dir, 
            self.keywords_dir, 
            self.signals
        )
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
    
    def update_log(self, text):
        """로그 텍스트 업데이트"""
        self.log_text.append(text)
        self.log_text.ensureCursorVisible()
    
    def update_summary(self, text):
        """요약 텍스트 업데이트"""
        self.summary_text.clear()
        self.summary_text.append(text)
        self.summary_text.ensureCursorVisible()
    
    def clear_text_areas(self):
        """텍스트 영역 초기화"""
        self.summary_text.clear()
        self.log_text.clear()
    
    def open_keyword_manager(self):
        """헤더 키워드 관리 도구 실행"""
        if not self.keyword_manager_path.exists():
            QMessageBox.critical(self, "오류", f"키워드 관리 도구를 찾을 수 없습니다: {self.keyword_manager_path}")
            return
        
        try:
            import subprocess
            subprocess.Popen([sys.executable, str(self.keyword_manager_path)])
        except Exception as e:
            QMessageBox.critical(self, "오류", f"키워드 관리 도구 실행 중 오류 발생: {str(e)}")
    
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
    
    def _create_default_keywords_if_needed(self):
        """기본 키워드 파일 생성"""
        # 더 많은 카테고리 키워드 추가
        default_keywords = [
            {
                "category": "financial",
                "blackList_keywords": [
                    r"(신원|개인정보|주민등록번호|계좌|OTP|신분증|카드).{0,5}(필수|정보|제출|확인|요청|제공)",
                    r"(계정|이용){0,5}(정지|제한)",
                    r"(입금|송금|출금){0,5}(요청|확인|기한)",
                    r"(즉시|바로|응답|확인){0,5}(응답|필수|확인)",
                    r"(세금|연금|보험료){0,5}(지급|환급|혜택|감면)",
                    r"(링크|첨부파일|다운로드|압축파일){0,10}(확인|필수|요망|클릭|참조)",
                    r"(비밀번호|인증번호).{0,10}(입력|확인|제출)",
                    r"(지금|즉시).{0,5}(실행|확인|다운로드)"
                ]
            },
            {
                "category": "delivery",
                "blackList_keywords": [
                    r"(배송|주소|도착|번호|물품|경로|실시간)\s{0,5}(정보|실패|지연|확인|오류)",
                    r"(수취인|위탁|운송장)\s{0,5}(부재|확인)",
                    r"(도착|반송|교환|환불|기간)\s{0,5}(예정|확인|정보)",
                    r"(링크|첨부파일|다운로드|압축파일)\s{0,10}(확인|필수|요망|클릭|참조)",
                    r"(비밀번호|인증번호).{0,10}(입력|확인|제출)",
                    r"(지금|즉시).{0,5}(실행|확인|다운로드)",
                    r"(우체국|택배|우편).{0,5}(배송|알림|안내)",
                    r"(패키지|소포).{0,5}(대기|보관|도착)"
                ]
            },
            {
                "category": "investigation",
                "blackList_keywords": [
                    r"(경찰서|경찰)(\s{0,5}(방문|조사|출석))?|((방문|조사|출석)\s{0,5})?(경찰서|경찰)",
                    r"(신분증)(\s{0,5}(발급|신청))?|((발급|신청)\s{0,5})?(신분증)"
                ]
            },
            {
                "category": "malicious",
                "blackList_keywords": [
                    r"\b(즉시|지금당장)\s{0,3}(클릭|다운로드)\b",
                    r"(비밀번호|주민번호)\s{0,5}입력\b",
                    r"\b(급속|중요)\s{0,3}조치\b"
                ]
            },
            {
                "category": "government",
                "blackList_keywords": [
                    r"(민원|증명서)\s{0,3}(발급|신청)",
                    r"(행정|국세청|세무서)\s{0,3}(안내|통보)",
                    r"(주민등록|여권)\s{0,3}(갱신|만료)",
                    r"(대회|경진대회|공모전)\s{0,5}(참가|신청|접수|안내)",
                    r"(운영위원회|정보|세종)\s{0,5}(알려드립|안내|통보)",
                    r"(국내|국제)\s{0,3}(대학생|참가자)\s{0,5}(모집|안내|접수)"
                ]
            },
            {
                "category": "military",
                "blackList_keywords": [
                    r"(군사|작전|훈련)\s{0,3}(기밀|문서|지침)",
                    r"(동원|병역|징집)\s{0,3}(안내|명령|통지)",
                    r"(군법|군사법원)\s{0,3}(소환|처분|판결)"
                ]
            },
            {
                "category": "education",
                "blackList_keywords": [
                    r"(학적|성적|장학금)\s{0,3}(변경|확인|지급)",
                    r"(입학|졸업|등록)\s{0,3}(안내|통보|확인)",
                    r"(학위|자격증)\s{0,3}(취득|인증|발급)"
                ]
            }
        ]

        for keyword_set in default_keywords:
            filename = f"{keyword_set['category']}_keywords.json"
            file_path = self.keywords_dir / filename
            if not file_path.exists():
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(keyword_set, f, ensure_ascii=False, indent=2)
                print(f"기본 키워드 파일 생성: {filename}")

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