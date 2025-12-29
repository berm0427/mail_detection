import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import re
from pathlib import Path


class KeywordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("헤더(제목) 기반 의심 키워드 관리")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # 설정 파일 경로
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keyword_config.json")
        
        # 데이터 초기화 - 기본값 (카테고리별 개별 키워드로 관리)
        self.project_path = tk.StringVar()
        self.keywords = {
            'financial': ['은행', '카드', '신한', '우리', '국민', '농협', '하나', 'bank', 'card'],
            'government': ['정부', '공공', '공단', '국세', '세무', '우체국', '우편', '코리아', '한국'],
            'delivery': ['택배', '배송', '패키지', '우체국', '우편', '한진', 'post', 'delivery'],
            'malicious': ['로그인', '계정', '인증', '비밀번호', '코드'],
            'general': ['주문확인', '결제확인', '긴급확인', '링크클릭']
        }
        self.category_var = tk.StringVar()
        self.keyword_var = tk.StringVar()
        
        # 설정 파일에서 이전 상태 로드
        self.load_saved_config()
        
        # UI 생성
        self.create_ui()

    def create_ui(self):
        # 프레임 설정
        frame = ttk.Frame(self.root, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 프로젝트 경로 선택
        path_frame = ttk.LabelFrame(frame, text="프로젝트 경로", padding=5)
        path_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Entry(path_frame, textvariable=self.project_path, width=60).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(path_frame, text="찾아보기", command=self.browse_project).pack(side=tk.RIGHT, padx=5)
        
        # 왼쪽 프레임 (카테고리 목록)
        left_frame = ttk.LabelFrame(frame, text="카테고리", padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 카테고리 트리뷰
        self.category_tree = ttk.Treeview(left_frame, columns=("category"), show="headings")
        self.category_tree.heading("category", text="카테고리명")
        self.category_tree.column("category", width=150)
        self.category_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 카테고리 선택 이벤트
        self.category_tree.bind("<<TreeviewSelect>>", self.on_category_select)
        
        # 카테고리 버튼
        cat_btn_frame = ttk.Frame(left_frame)
        cat_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(cat_btn_frame, text="추가", command=self.add_category_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(cat_btn_frame, text="삭제", command=self.remove_category).pack(side=tk.LEFT, padx=2)
        
        # 오른쪽 프레임 (키워드 목록)
        right_frame = ttk.LabelFrame(frame, text="키워드", padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 키워드 리스트박스
        self.keyword_listbox = tk.Listbox(right_frame)
        self.keyword_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 키워드 추가 프레임
        keyword_entry_frame = ttk.Frame(right_frame)
        keyword_entry_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(keyword_entry_frame, text="새 키워드:").pack(side=tk.LEFT, padx=2)
        ttk.Entry(keyword_entry_frame, textvariable=self.keyword_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # 키워드 버튼
        key_btn_frame = ttk.Frame(right_frame)
        key_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(key_btn_frame, text="추가", command=self.add_keyword).pack(side=tk.LEFT, padx=2)
        ttk.Button(key_btn_frame, text="삭제", command=self.remove_keyword).pack(side=tk.LEFT, padx=2)
        
        # 하단 버튼 프레임
        bottom_frame = ttk.Frame(frame)
        bottom_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(bottom_frame, text="소스 코드 업데이트", command=self.update_source_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="키워드 저장", command=self.save_keywords).pack(side=tk.LEFT, padx=5)
        ttk.Button(bottom_frame, text="키워드 불러오기", command=self.load_keywords).pack(side=tk.LEFT, padx=5)
        
        # 초기 데이터 로드
        self.update_category_tree()
    
    def browse_project(self):
        folder_path = filedialog.askdirectory(title="프로젝트 루트 디렉토리 선택")
        if folder_path:
            self.project_path.set(folder_path)
    
    def update_category_tree(self):
        # 트리뷰 초기화
        for item in self.category_tree.get_children():
            self.category_tree.delete(item)
        
        # 카테고리 추가
        for category in self.keywords.keys():
            self.category_tree.insert("", "end", values=(category,))
    
    def update_keyword_listbox(self, category):
        # 리스트박스 초기화
        self.keyword_listbox.delete(0, tk.END)
        
        # 선택된 카테고리의 키워드 추가
        if category in self.keywords:
            for keyword in self.keywords[category]:
                self.keyword_listbox.insert(tk.END, keyword)
    
    def on_category_select(self, event):
        selected_items = self.category_tree.selection()
        if selected_items:
            category = self.category_tree.item(selected_items[0])["values"][0]
            self.category_var.set(category)
            self.update_keyword_listbox(category)
    
    def add_category_dialog(self):
        # 간단한 다이얼로그 창 생성
        dialog = tk.Toplevel(self.root)
        dialog.title("카테고리 추가")
        dialog.geometry("300x100")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="새 카테고리명:").pack(padx=10, pady=10)
        
        category_entry = ttk.Entry(dialog, width=30)
        category_entry.pack(padx=10, pady=5)
        category_entry.focus_set()
        
        def ok_command():
            category = category_entry.get().strip()
            if category:
                self.add_category(category)
                dialog.destroy()
            else:
                messagebox.showwarning("경고", "카테고리명을 입력하세요.")
        
        ttk.Button(dialog, text="확인", command=ok_command).pack(pady=10)
        
        # Enter 키 바인딩
        dialog.bind("<Return>", lambda event: ok_command())
    
    def add_category(self, category):
        if category in self.keywords:
            messagebox.showinfo("알림", f"카테고리 '{category}'는 이미 존재합니다.")
            return
        
        self.keywords[category] = []
        self.update_category_tree()
        
        # 설정 파일 자동 저장
        self.save_config()
        messagebox.showinfo("알림", f"카테고리 '{category}'가 추가되었습니다.")
    
    def remove_category(self):
        selected_items = self.category_tree.selection()
        if not selected_items:
            messagebox.showwarning("경고", "삭제할 카테고리를 선택하세요.")
            return
        
        category = self.category_tree.item(selected_items[0])["values"][0]
        
        if messagebox.askyesno("확인", f"카테고리 '{category}'를 삭제하시겠습니까?"):
            del self.keywords[category]
            self.update_category_tree()
            self.keyword_listbox.delete(0, tk.END)
            
            # 설정 파일 자동 저장
            self.save_config()
            messagebox.showinfo("알림", f"카테고리 '{category}'가 삭제되었습니다.")
            
            # 프로젝트 경로가 설정되어 있으면 자동 업데이트
            if self.project_path.get():
                self.update_source_files()
    
    def add_keyword(self):
        category = self.category_var.get()
        if not category:
            messagebox.showwarning("경고", "카테고리를 선택하세요.")
            return
        
        keyword = self.keyword_var.get().strip()
        if not keyword:
            messagebox.showwarning("경고", "키워드를 입력하세요.")
            return
        
        if keyword in self.keywords[category]:
            messagebox.showinfo("알림", f"키워드 '{keyword}'는 이미 존재합니다.")
            return
        
        self.keywords[category].append(keyword)
        self.update_keyword_listbox(category)
        self.keyword_var.set("")  # 입력 필드 초기화
        
        # 설정 파일 자동 저장
        self.save_config()
        
        messagebox.showinfo("알림", f"키워드 '{keyword}'가 추가되었습니다.")
        
        # 프로젝트 경로가 설정되어 있으면 자동 업데이트
        if self.project_path.get():
            self.update_source_files()
    
    def remove_keyword(self):
        category = self.category_var.get()
        if not category:
            messagebox.showwarning("경고", "카테고리를 선택하세요.")
            return
        
        selected_indices = self.keyword_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("경고", "삭제할 키워드를 선택하세요.")
            return
        
        keyword = self.keyword_listbox.get(selected_indices[0])
        
        if messagebox.askyesno("확인", f"키워드 '{keyword}'를 삭제하시겠습니까?"):
            self.keywords[category].remove(keyword)
            self.update_keyword_listbox(category)
            
            # 설정 파일 자동 저장
            self.save_config()
            
            messagebox.showinfo("알림", f"키워드 '{keyword}'가 삭제되었습니다.")
            
            # 프로젝트 경로가 설정되어 있으면 자동 업데이트
            if self.project_path.get():
                self.update_source_files()
    
    def save_keywords(self):
        """키워드를 파일로 저장하고 소스코드를 업데이트합니다."""
        try:
            # 프로젝트 경로 확인
            if not self.project_path.get():
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON 파일", "*.json"), ("모든 파일", "*.*")],
                    title="키워드 저장"
                )
                
                if not file_path:
                    return False
                
                # 키워드만 저장
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.keywords, f, ensure_ascii=False, indent=2)
                
                messagebox.showinfo("알림", f"키워드가 {file_path}에 저장되었습니다.")
                return True
            else:
                # 소스코드와 설정 업데이트
                success = self.update_source_files()
                return success
                
        except Exception as e:
            messagebox.showerror("오류", f"저장 중 오류가 발생했습니다: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def load_keywords(self):
        """키워드 파일을 불러옵니다."""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON 파일", "*.json"), ("모든 파일", "*.*")],
            title="키워드 불러오기"
        )
        
        if not file_path:
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
            
            # 키워드 형식 검증
            if not isinstance(loaded_data, dict):
                messagebox.showwarning("경고", "잘못된 키워드 파일 형식입니다.")
                return False
            
            # 키워드 업데이트
            self.keywords = loaded_data
            
            # UI 업데이트
            self.update_category_tree()
            self.keyword_listbox.delete(0, tk.END)
            
            # 설정 파일 업데이트
            self.save_config()
            
            # 프로젝트 경로가 있으면 소스코드 업데이트
            if self.project_path.get():
                self.update_source_files()
            
            messagebox.showinfo("알림", f"키워드가 {file_path}에서 로드되었습니다.")
            return True
            
        except Exception as e:
            messagebox.showerror("오류", f"로드 중 오류가 발생했습니다: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def save_config(self):
        """현재 상태를 설정 파일에 저장합니다."""
        try:
            from datetime import datetime
            
            config = {
                "project_path": self.project_path.get(),
                "keywords": self.keywords,
                "last_saved": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                
            print(f"설정 저장됨: {self.config_file}")
            return True
        except Exception as e:
            print(f"설정 저장 중 오류: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def load_saved_config(self):
        """설정 파일에서 이전 상태를 로드하고, 필요한 경우 소스 코드에서 현재 키워드를 가져옵니다."""
        try:
            # 먼저 소스 코드에서 현재 키워드 추출 시도
            self.extract_keywords_from_source()
            
            # 그 다음 설정 파일에서 로드 (설정 파일이 있으면 이것이 우선함)
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 프로젝트 경로 설정
                if "project_path" in config and os.path.exists(config["project_path"]):
                    self.project_path.set(config["project_path"])
                    print(f"프로젝트 경로 로드됨: {config['project_path']}")
                
                # 키워드 설정
                if "keywords" in config and isinstance(config["keywords"], dict):
                    self.keywords = config["keywords"]
                    print(f"키워드 로드됨: {len(self.keywords)} 카테고리")
                
        except Exception as e:
            print(f"설정 로드 중 오류: {e}")
            import traceback
            traceback.print_exc()

    def extract_keywords_from_source(self):
        """소스 코드에서 현재 사용 중인 키워드를 추출합니다 (딕셔너리 형태)."""
        try:
            # 프로젝트 경로가 설정되어 있지 않으면 건너뜀
            if not self.project_path.get() or not os.path.exists(self.project_path.get()):
                return
            
            project_root = Path(self.project_path.get())
            integration_path = project_root / "email_analyzer" / "integration.py"
            header_detection_path = project_root / "mail_header" / "mail_header_detection_v4.py"
            
            if not integration_path.exists():
                print(f"integration.py 파일을 찾을 수 없습니다: {integration_path}")
                return
                
            if not header_detection_path.exists():
                print(f"header_detection 파일을 찾을 수 없습니다: {header_detection_path}")
                return
            
            # 두 파일 내용 읽기
            with open(integration_path, 'r', encoding='utf-8') as f:
                content_I = f.read()
            
            with open(header_detection_path, 'r', encoding='utf-8') as f:
                content_H = f.read()
            
            # 패턴 검색 함수
            def extract_patterns_from_content(content, file_name):
                """파일 내용에서 패턴 딕셔너리 추출"""
                patterns_found = {}
                
                # subject_suspicious_patterns 딕셔너리 찾기
                pattern = r"subject_suspicious_patterns\s*=\s*\{(.*?)\}"
                matches = re.search(pattern, content, re.DOTALL)
                
                if matches:
                    print(f"{file_name}에서 subject_suspicious_patterns 발견")
                    patterns_found.update(self._parse_patterns_block(matches.group(1), "subject_suspicious_patterns"))
                
                # SUSPICIOUS_PATTERNS 클래스 변수도 찾기
                pattern2 = r"SUSPICIOUS_PATTERNS\s*=\s*\{(.*?)\}"
                matches2 = re.search(pattern2, content, re.DOTALL)
                
                if matches2:
                    print(f"{file_name}에서 SUSPICIOUS_PATTERNS 발견")
                    patterns_found.update(self._parse_patterns_block(matches2.group(1), "SUSPICIOUS_PATTERNS"))
                
                return patterns_found
            
            # 두 파일에서 패턴 추출
            patterns_I = extract_patterns_from_content(content_I, "integration.py")
            patterns_H = extract_patterns_from_content(content_H, "mail_header_detection_v4.py")
            
            # 패턴 병합 (integration.py 우선, header_detection으로 보완)
            combined_patterns = {}
            combined_patterns.update(patterns_H)  # header_detection 패턴 먼저
            combined_patterns.update(patterns_I)  # integration.py 패턴으로 덮어쓰기 (우선순위)
            
            if not combined_patterns:
                print("두 파일 모두에서 패턴 딕셔너리를 찾을 수 없습니다.")
                return
            
            # 추출된 카테고리 패턴으로 키워드 딕셔너리 업데이트
            if combined_patterns:
                self.keywords = combined_patterns
                print(f"소스 코드에서 추출한 키워드 카테고리: {list(combined_patterns.keys())}")
                print(f"총 키워드 수: {sum(len(keywords) for keywords in combined_patterns.values())}")
                
        except Exception as e:
            print(f"소스 코드에서 키워드 추출 중 오류: {e}")
            import traceback
            traceback.print_exc()

    def _parse_patterns_block(self, patterns_block, dict_name):
        """패턴 블록에서 카테고리별 키워드 추출"""
        category_patterns = {}
        
        try:
            # 멀티라인 카테고리 패턴 처리
            current_category = None
            current_patterns = []
            bracket_depth = 0
            
            lines = patterns_block.split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 카테고리 시작 찾기 ('category': [)
                category_start_match = re.search(r"'(\w+)':\s*\[", line)
                if category_start_match:
                    # 이전 카테고리 저장
                    if current_category and current_patterns:
                        category_patterns[current_category] = current_patterns
                    
                    # 새 카테고리 시작
                    current_category = category_start_match.group(1)
                    current_patterns = []
                    bracket_depth = line.count('[') - line.count(']')
                    
                    # 같은 라인에 패턴이 있는지 확인
                    remaining_line = line[category_start_match.end():]
                    current_patterns.extend(self._extract_keywords_from_line(remaining_line))
                    
                elif current_category is not None:
                    # 현재 카테고리의 패턴 계속 수집
                    bracket_depth += line.count('[') - line.count(']')
                    current_patterns.extend(self._extract_keywords_from_line(line))
                    
                    # 카테고리 끝 (괄호 닫힘)
                    if bracket_depth <= 0:
                        if current_patterns:
                            category_patterns[current_category] = current_patterns
                        current_category = None
                        current_patterns = []
            
            # 마지막 카테고리 저장
            if current_category and current_patterns:
                category_patterns[current_category] = current_patterns
                
            print(f"{dict_name}에서 추출된 카테고리: {list(category_patterns.keys())}")
            
        except Exception as e:
            print(f"패턴 블록 파싱 오류: {e}")
        
        return category_patterns

    def _extract_keywords_from_line(self, line):
        """라인에서 키워드 추출"""
        keywords = []
        
        # 정규식 패턴에서 키워드 추출 (r'패턴' 또는 '패턴' 형태)
        pattern_matches = re.findall(r"r?['\"]([^'\"]+)['\"]", line)
        
        for pattern in pattern_matches:
            # 정규식 특수문자 제거하고 키워드 추출
            # '|' 구분자로 나눠진 키워드들
            if '|' in pattern:
                parts = pattern.split('|')
                for part in parts:
                    # 정규식 패턴 정리
                    keyword = re.sub(r'[\\()\[\].*+?^${}]', '', part).strip()
                    if keyword and len(keyword) > 1 and keyword not in keywords:
                        keywords.append(keyword)
            else:
                # 단일 키워드 또는 패턴
                # 정규식에서 실제 키워드 추출
                clean_pattern = re.sub(r'[\\()\[\].*+?^${}]', ' ', pattern)
                words = clean_pattern.split()
                for word in words:
                    if word and len(word) > 1 and word not in keywords:
                        keywords.append(word)
        
        return keywords
    
    def update_source_files(self):
        """헤더 분석에 사용되는 소스 코드 내 키워드를 업데이트합니다."""
        project_path = self.project_path.get()
        if not project_path:
            messagebox.showwarning("경고", "프로젝트 경로를 선택하세요.")
            return False
        
        project_root = Path(project_path)
        if not project_root.exists():
            messagebox.showwarning("경고", f"프로젝트 경로가 존재하지 않습니다: {project_path}")
            return False
        
        print(f"프로젝트 루트: {project_root}")
        
        # 소스 코드 파일 경로
        integration_path = project_root / "email_analyzer" / "integration.py"
        header_detection_path = project_root / "mail_header" / "mail_header_detection_v4.py"
        
        print(f"통합 경로: {integration_path} (존재: {integration_path.exists()})")
        print(f"헤더 분석 경로: {header_detection_path} (존재: {header_detection_path.exists()})")
        
        # 파일 백업 생성
        success_count = 0
        total_files = 0
        
        try:
            # integration.py 파일 업데이트
            if integration_path.exists():
                total_files += 1
                # 백업 생성
                backup_path = integration_path.with_suffix('.bak.py')
                import shutil
                shutil.copy2(integration_path, backup_path)
                print(f"integration.py 백업 생성: {backup_path}")
                
                # 딕셔너리 형태의 제목 패턴 업데이트
                success = self.update_subject_patterns_dict_in_file(
                    integration_path,
                    "subject_suspicious_patterns",
                    self.keywords
                )
                
                if success:
                    success_count += 1
                print(f"integration.py 업데이트 결과: {success}")
            
            # mail_header_detection_v4.py 파일 업데이트 (동일한 변수명 사용)
            if header_detection_path.exists():
                total_files += 1
                # 백업 생성
                backup_path = header_detection_path.with_suffix('.bak.py')
                import shutil
                shutil.copy2(header_detection_path, backup_path)
                print(f"mail_header_detection_v4.py 백업 생성: {backup_path}")
                
                # subject_suspicious_patterns 딕셔너리 업데이트 (SUSPICIOUS_PATTERNS가 아님)
                success = self.update_subject_patterns_dict_in_file(
                    header_detection_path,
                    "subject_suspicious_patterns",  # 변경: SUSPICIOUS_PATTERNS → subject_suspicious_patterns
                    self.keywords
                )
                
                if success:
                    success_count += 1
                print(f"mail_header_detection_v4.py 업데이트 결과: {success}")
            
            if total_files == 0:
                messagebox.showwarning("경고", "업데이트할 파일을 찾을 수 없습니다.")
                return False
            
            # 설정 저장 (키워드와 프로젝트 경로)
            self.save_config()
            
            if success_count == total_files:
                # GUI 프로그램 재시작 확인
                self.check_and_restart_main_gui()
                
                messagebox.showinfo("알림", f"소스 코드 {success_count}/{total_files} 파일이 업데이트되었습니다.")
                return True
            else:
                messagebox.showerror("오류", f"소스 코드 업데이트에 일부 실패했습니다. ({success_count}/{total_files})")
                return False
            
        except Exception as e:
            messagebox.showerror("오류", f"소스 코드 업데이트 중 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def update_subject_patterns_dict_in_file(self, file_path, pattern_var_name, keywords_dict):
        """subject_suspicious_patterns 변수를 딕셔너리 형태로 생성하여 덮어씁니다."""
        try:
            print(f"\n{file_path.name}에서 {pattern_var_name} 딕셔너리 업데이트 시작")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 기존 패턴 변수 찾기 (딕셔너리 형태)
            pattern_regex = r"(\s+)" + pattern_var_name + r"\s*=\s*\{(.*?)\}"
            pattern_match = re.search(pattern_regex, content, re.DOTALL)
            
            if not pattern_match:
                print(f"{pattern_var_name} 딕셔너리 변수를 찾을 수 없습니다.")
                return False
            
            # 들여쓰기 추출
            indentation = pattern_match.group(1)
            
            # 새로운 딕셔너리 코드 생성
            subject_patterns_code = pattern_var_name + " = {\n"
            
            # 카테고리별 키워드를 딕셔너리 형태로 생성
            for category, keywords in keywords_dict.items():
                if keywords:
                    # 카테고리별 주석 추가
                    subject_patterns_code += f"{indentation}    # {category} 카테고리 키워드\n"
                    
                    # 각 키워드를 정규식 OR 연산자(|)로 연결한 패턴 생성
                    pattern = '|'.join([re.escape(kw) for kw in keywords])
                    subject_patterns_code += f"{indentation}    '{category}': [\n"
                    subject_patterns_code += f"{indentation}        r'{pattern}'\n"
                    subject_patterns_code += f"{indentation}    ],\n"
            
            # 기본 의심 패턴 추가
            subject_patterns_code += f"{indentation}    # 기본 의심 패턴\n"
            subject_patterns_code += f"{indentation}    'general': [\n"
            subject_patterns_code += f"{indentation}        r'(주문|결제).*확인',\n"
            subject_patterns_code += f"{indentation}        r'(지금|즉시).*확인',\n"
            subject_patterns_code += f"{indentation}        r'링크.*클릭',\n"
            subject_patterns_code += f"{indentation}        r'비밀번호|인증|코드'\n"
            subject_patterns_code += f"{indentation}    ]\n"
            subject_patterns_code += f"{indentation}}}"
            
            # 패턴 변수 업데이트
            new_content = content[:pattern_match.start()] + indentation + subject_patterns_code + content[pattern_match.end():]
            
            # 원본 파일 내용 업데이트
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"{pattern_var_name} 딕셔너리 변수 업데이트 완료")
            return True
        
        except Exception as e:
            print(f"{file_path.name} 파일 업데이트 중 오류: {e}")
            import traceback
            traceback.print_exc()
            return False

    def check_and_restart_main_gui(self):
        """main_gui.py가 실행 중인지 확인하고, 재시작합니다."""
        try:
            import subprocess
            import sys
            import time
            import psutil
            import os
            
            # 디버깅을 위한 로그 추가
            print("프로세스 검색 시작...")
            
            main_gui_running = False
            main_gui_pid = None
            found_processes = []  # 디버깅용
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    cmdline = proc_info.get('cmdline', [])
                    
                    # 더 포괄적인 Python 프로세스 검색
                    if any(name in proc_name for name in ['python', 'py.exe']):
                        # 디버깅 정보 수집
                        cmdline_str = ' '.join(cmdline) if cmdline else ''
                        found_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_name,
                            'cmdline': cmdline_str
                        })
                        
                        # main_gui.py 찾기 (더 유연한 검색)
                        if cmdline and any('main_gui.py' in str(arg) or 
                                         arg.endswith('main_gui.py') for arg in cmdline):
                            main_gui_running = True
                            main_gui_pid = proc_info['pid']
                            print(f"main_gui.py 프로세스 발견: PID {main_gui_pid}")
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    continue
            
            # 디버깅 정보 출력
            print(f"발견된 Python 프로세스들: {len(found_processes)}개")
            for proc in found_processes:
                print(f"  PID: {proc['pid']}, Name: {proc['name']}, CMD: {proc['cmdline'][:100]}...")
            
            if main_gui_running and main_gui_pid:
                print("main_gui.py 프로세스 발견됨 - 재시작 대화상자 표시")
                # 사용자에게 재시작 확인
                if messagebox.askyesno("GUI 재시작", "변경사항을 적용하려면 메인 GUI를 재시작해야 합니다. 재시작하시겠습니까?"):
                    try:
                        process = psutil.Process(main_gui_pid)
                        process.terminate()
                        
                        print(f"main_gui.py 프로세스(PID: {main_gui_pid}) 종료 중...")
                        process.wait(timeout=5)
                        print("프로세스 종료 완료")
                        
                        time.sleep(1)
                        
                        # 메인 GUI 다시 시작
                        main_gui_path = self.get_main_gui_path()
                        if main_gui_path and main_gui_path.exists():
                            print(f"main_gui.py 재시작: {main_gui_path}")
                            # Windows에서 더 안정적인 실행 방식
                            if os.name == 'nt':  # Windows
                                subprocess.Popen([sys.executable, str(main_gui_path)], 
                                               creationflags=subprocess.CREATE_NEW_CONSOLE)
                            else:
                                subprocess.Popen([sys.executable, str(main_gui_path)])
                        else:
                            messagebox.showwarning("경고", "main_gui.py 경로를 찾을 수 없어 자동 재시작할 수 없습니다.")
                            
                    except psutil.NoSuchProcess:
                        print("프로세스가 이미 종료됨")
                    except Exception as e:
                        print(f"프로세스 재시작 중 오류: {e}")
                        messagebox.showwarning("경고", f"GUI 재시작 중 오류 발생: {e}")
            else:
                print("main_gui.py 프로세스를 찾을 수 없음")
                # 수동 재시작 안내
                messagebox.showinfo("알림", "main_gui.py 프로세스를 찾을 수 없습니다.\n변경사항 적용을 위해 수동으로 메인 GUI를 재시작해주세요.")
                
        except ImportError:
            print("psutil 모듈 없음")
            messagebox.showinfo("알림", "psutil 모듈이 필요합니다. 'pip install psutil'로 설치하세요.")
        except Exception as e:
            print(f"GUI 재시작 확인 중 오류: {e}")
            messagebox.showerror("오류", f"GUI 재시작 확인 중 오류: {e}")
    
    def get_main_gui_path(self):
        """main_gui.py 파일 경로를 찾습니다."""
        try:
            # 현재 스크립트 경로에서 찾기
            script_dir = Path(__file__).parent
            main_gui_path = script_dir / "main_gui.py"
            
            if main_gui_path.exists():
                return main_gui_path
            
            # 프로젝트 경로에서 찾기
            if self.project_path.get():
                project_root = Path(self.project_path.get())
                main_gui_path = project_root / "main_gui.py"
                
                if main_gui_path.exists():
                    return main_gui_path
            
            return None
        except Exception as e:
            print(f"main_gui.py 경로 찾기 오류: {e}")
            return None

if __name__ == "__main__":
    root = tk.Tk()
    app = KeywordManager(root)
    root.mainloop()