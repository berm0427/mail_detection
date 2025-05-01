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
        
        # 데이터 초기화 - 기본값
        self.project_path = tk.StringVar()
        self.keywords = {
            'financial': ['은행', '카드', '신한', '우리', '국민', '농협', '하나', 'bank', 'card'],
            'government': ['정부', '공공', '공단', '국세', '세무', '우체국', '우편', '코리아', '한국'],
            'delivery': ['택배', '배송', '패키지', '우체국', '우편', '한진', 'post', 'delivery'],
            'tech': ['microsoft', 'apple', 'google', 'facebook', 'meta', 'amazon']
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
        
        # 하단 버튼
        bottom_frame = ttk.Frame(frame)
        bottom_frame.pack(fill=tk.X, padx=5, pady=10)
        
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
            from datetime import datetime  # 함수 내에서 임포트
            
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
        """소스 코드에서 현재 사용 중인 키워드를 추출합니다."""
        try:
            # 프로젝트 경로가 설정되어 있지 않으면 건너뜀
            if not self.project_path.get() or not os.path.exists(self.project_path.get()):
                return
            
            project_root = Path(self.project_path.get())
            integration_path = project_root / "email_analyzer" / "integration.py"
            
            if not integration_path.exists():
                print(f"integration.py 파일을 찾을 수 없습니다: {integration_path}")
                return
            
            with open(integration_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # subject_suspicious_patterns 변수 찾기
            pattern = r"subject_suspicious_patterns\s*=\s*\[(.*?)\]"
            matches = re.search(pattern, content, re.DOTALL)
            
            if not matches:
                print("subject_suspicious_patterns 변수를 찾을 수 없습니다.")
                return
            
            patterns_block = matches.group(1)
            
            # 카테고리별 패턴 추출
            category_patterns = {}
            current_category = None
            
            for line in patterns_block.split('\n'):
                line = line.strip()
                
                # 카테고리 주석 찾기
                category_match = re.search(r'#\s*(\w+)\s*카테고리', line)
                if category_match:
                    current_category = category_match.group(1)
                    category_patterns[current_category] = []
                    continue
                
                # 패턴 라인 찾기
                if line.startswith('r\'') or line.startswith('r"'):
                    # 정규식 패턴에서 키워드 추출
                    pattern_match = re.search(r'r[\'"](.+?)[\'"]', line)
                    if pattern_match and current_category:
                        pattern = pattern_match.group(1)
                        # '|' 구분자로 나눠진 키워드 추출
                        keywords = pattern.split('|')
                        for keyword in keywords:
                            # 정규식 이스케이프 문자 제거
                            keyword = re.sub(r'\\', '', keyword)
                            if keyword and keyword not in category_patterns[current_category]:
                                category_patterns[current_category].append(keyword)
            
            # 추출된 카테고리 패턴으로 키워드 딕셔너리 업데이트
            if category_patterns:
                self.keywords = category_patterns
                print(f"소스 코드에서 추출한 키워드: {self.keywords}")
                
        except Exception as e:
            print(f"소스 코드에서 키워드 추출 중 오류: {e}")
            import traceback
            traceback.print_exc()
    
    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 마지막으로 저장된 키워드 파일 로드
                if "last_saved_file" in config and os.path.exists(config["last_saved_file"]):
                    self.last_saved_file = config["last_saved_file"]
                    with open(self.last_saved_file, 'r', encoding='utf-8') as f:
                        self.keywords = json.load(f)
                    print(f"키워드 파일 로드됨: {self.last_saved_file}")
                
                # 프로젝트 경로 설정
                if "last_project_path" in config and os.path.exists(config["last_project_path"]):
                    self.project_path.set(config["last_project_path"])
                    print(f"프로젝트 경로 설정됨: {config['last_project_path']}")
        except Exception as e:
            print(f"설정 로드 중 오류: {e}")
            messagebox.showerror("설정 로드 오류", f"설정 파일을 불러오는 중 오류가 발생했습니다: {e}")
    
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
        header_analyzer_path = project_root / "mail_header" / "mail_header_detection_v4.py"
        
        print(f"통합 경로: {integration_path} (존재: {integration_path.exists()})")
        print(f"헤더 분석기 경로: {header_analyzer_path} (존재: {header_analyzer_path.exists()})")
        
        # 파일 백업 생성
        success = False
        
        try:
            # integration.py 파일 업데이트
            if integration_path.exists():
                # 백업 생성
                backup_path = integration_path.with_suffix('.bak.py')
                import shutil
                shutil.copy2(integration_path, backup_path)
                print(f"integration.py 백업 생성: {backup_path}")
                
                # 제목 패턴 업데이트 - impersonation_keywords 대신 subject_suspicious_patterns만 사용
                success_subj = self.update_subject_patterns_in_file(
                    integration_path,
                    "analyze_email",
                    "subject_suspicious_patterns",
                    self.keywords
                )
                
                success = success_subj
                print(f"integration.py 업데이트 결과: subject_patterns={success_subj}")
            else:
                messagebox.showwarning("경고", f"파일을 찾을 수 없습니다: {integration_path}")
            
            # mail_header_detection_v4.py 파일 업데이트 - impersonation_keywords 대신 subject_suspicious_patterns 사용
            if header_analyzer_path.exists():
                # 백업 생성
                backup_path = header_analyzer_path.with_suffix('.bak.py')
                import shutil
                shutil.copy2(header_analyzer_path, backup_path)
                print(f"mail_header_detection_v4.py 백업 생성: {backup_path}")
                
                # 제목 패턴 업데이트
                success_header = self.update_subject_patterns_in_file(
                    header_analyzer_path,
                    "analyze_sender_name",  # 적절한 함수 이름으로 변경하세요
                    "suspicious_patterns",  # 헤더 분석기에서 사용하는 변수 이름으로 변경하세요
                    self.keywords
                )
                success = success or success_header
                print(f"mail_header_detection_v4.py 업데이트 결과: {success_header}")
            else:
                messagebox.showwarning("경고", f"파일을 찾을 수 없습니다: {header_analyzer_path}")
            
            # 설정 저장 (키워드와 프로젝트 경로)
            self.save_config()
            
            if success:
                # GUI 프로그램 재시작 확인
                self.check_and_restart_main_gui()
                
                messagebox.showinfo("알림", "소스 코드가 업데이트되었습니다.")
                return True
            else:
                messagebox.showerror("오류", "소스 코드 업데이트에 실패했습니다.")
                return False
            
        except Exception as e:
            messagebox.showerror("오류", f"소스 코드 업데이트 중 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def check_and_restart_main_gui(self):
        """main_gui.py가 실행 중인지 확인하고, 재시작합니다."""
        try:
            import subprocess
            import sys
            import time
            import psutil  # 이 모듈이 없다면 pip install psutil로 설치 필요
            
            # main_gui.py 프로세스 찾기
            main_gui_running = False
            main_gui_pid = None
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # Python 프로세스 중 main_gui.py를 실행 중인 것 찾기
                    if proc.info['name'] == 'python.exe' or proc.info['name'] == 'pythonw.exe':
                        cmdline = proc.info['cmdline']
                        if cmdline and any('main_gui.py' in arg for arg in cmdline):
                            main_gui_running = True
                            main_gui_pid = proc.info['pid']
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            if main_gui_running and main_gui_pid:
                # 사용자에게 재시작 확인
                if messagebox.askyesno("GUI 재시작", "변경사항을 적용하려면 메인 GUI를 재시작해야 합니다. 재시작하시겠습니까?"):
                    # 프로세스 종료
                    try:
                        process = psutil.Process(main_gui_pid)
                        process.terminate()
                        
                        # 프로세스 종료 대기
                        print(f"main_gui.py 프로세스(PID: {main_gui_pid}) 종료 중...")
                        process.wait(timeout=5)
                        print("프로세스 종료 완료")
                        
                        # 약간의 지연 후 다시 시작
                        time.sleep(1)
                        
                        # 메인 GUI 다시 시작
                        main_gui_path = self.get_main_gui_path()
                        if main_gui_path and main_gui_path.exists():
                            print(f"main_gui.py 재시작: {main_gui_path}")
                            subprocess.Popen([sys.executable, str(main_gui_path)])
                        else:
                            messagebox.showwarning("경고", "main_gui.py 경로를 찾을 수 없어 자동 재시작할 수 없습니다.")
                            
                    except psutil.NoSuchProcess:
                        print("프로세스가 이미 종료됨")
                    except Exception as e:
                        print(f"프로세스 재시작 중 오류: {e}")
                        messagebox.showwarning("경고", f"GUI 재시작 중 오류 발생: {e}")
            
        except ImportError:
            messagebox.showinfo("알림", "psutil 모듈이 필요합니다. 'pip install psutil'로 설치하세요.")
        except Exception as e:
            print(f"GUI 재시작 확인 중 오류: {e}")

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
    
    def generate_keywords_code(self):
        """키워드 코드를 생성합니다."""
        keywords_code = "{\n"
        for category, words in self.keywords.items():
            words_repr = ", ".join([f"'{word}'" for word in words])
            keywords_code += f"    '{category}': [{words_repr}],\n"
        keywords_code += "}"
        return keywords_code
    
    def update_function_in_file(self, file_path, function_name, keyword_var_name, keywords_code):
        """특정 함수 내의 키워드 변수 정의를 업데이트합니다."""
        try:
            print(f"\n{file_path.name}의 {function_name} 함수에서 {keyword_var_name} 업데이트 시작")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 함수 정의 찾기
            function_pattern = r"def\s+" + function_name + r"\s*\([^)]*\):"
            function_match = re.search(function_pattern, content)
            
            if not function_match:
                print(f"{file_path.name}에서 {function_name} 함수를 찾을 수 없습니다.")
                return False
            
            function_start = function_match.start()
            print(f"함수 시작 위치: {function_start}")
            
            # 함수 내용 찾기 (들여쓰기 레벨로 함수 끝 감지)
            lines = content[function_start:].splitlines()
            function_end = function_start
            function_body = ""
            
            # 함수 첫 줄 들여쓰기 레벨 찾기
            first_line_indent = 0
            for i, line in enumerate(lines):
                if i > 0 and line.strip():  # 첫번째 실제 코드 라인
                    first_line_indent = len(line) - len(line.lstrip())
                    break
            
            print(f"함수 들여쓰기 레벨: {first_line_indent}")
            
            # 함수 본문 추출
            in_function = False
            for i, line in enumerate(lines):
                function_end += len(line) + 1  # +1 for newline
                
                # 함수 시작 확인
                if i == 0:
                    function_body += line + "\n"
                    in_function = True
                    continue
                
                # 빈 줄 처리
                if not line.strip():
                    function_body += line + "\n"
                    continue
                
                # 현재 줄의 들여쓰기 확인
                curr_indent = len(line) - len(line.lstrip())
                
                # 함수가 끝났는지 확인 (들여쓰기가 줄어들었을 때)
                if in_function and curr_indent < first_line_indent:
                    function_end -= len(line) + 1  # 함수 끝 조정
                    break
                
                function_body += line + "\n"
            
            print(f"함수 본문 길이: {len(function_body)}")
            
            # 함수 내에서 키워드 변수 찾기
            keyword_pattern = r"(\s+)" + keyword_var_name + r"\s*=\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}"
            keyword_match = re.search(keyword_pattern, function_body)
            
            if keyword_match:
                print(f"키워드 변수 {keyword_var_name} 찾음: 위치 {keyword_match.start()}-{keyword_match.end()}")
                # 들여쓰기 추출
                indentation = keyword_match.group(1)
                
                # 키워드 코드에 들여쓰기 적용
                indented_code = keywords_code.replace("\n", "\n" + indentation)
                
                # 변수 이름 추가
                indented_code = indentation + keyword_var_name + " = " + indented_code
                
                # 키워드 정의 교체
                new_function_body = function_body.replace(keyword_match.group(0), indented_code)
                
                # 원본 파일 내용 업데이트
                new_content = content[:function_start] + new_function_body + content[function_end:]
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                print(f"{file_path.name}의 {keyword_var_name} 업데이트 완료")
                return True
            else:
                print(f"키워드 변수 {keyword_var_name}를 찾을 수 없어 새로 추가합니다")
                # 키워드 변수 정의를 찾지 못한 경우, 함수 시작 부분에 추가
                lines = function_body.splitlines()
                
                # 함수 선언 다음 줄에 키워드 추가
                indentation = " " * (first_line_indent + 4)  # 추가 들여쓰기
                indented_code = keywords_code.replace("\n", "\n" + indentation)
                indented_code = indentation + keyword_var_name + " = " + indented_code
                
                new_lines = [lines[0], "", indented_code] + lines[1:]
                new_function_body = "\n".join(new_lines)
                
                # 원본 파일 내용 업데이트
                new_content = content[:function_start] + new_function_body + content[function_end:]
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                print(f"{file_path.name}에 새 {keyword_var_name} 변수 추가 완료")
                return True
                
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"{file_path.name} 파일 업데이트 중 오류: {e}\n{error_details}")
            return False
    
    def update_subject_patterns_in_file(self, file_path, function_name, pattern_var_name, keywords_dict):
        """subject_suspicious_patterns 변수를 새로 생성하여 덮어씁니다."""
        try:
            print(f"\n{file_path.name}의 {function_name} 함수에서 {pattern_var_name} 업데이트 시작")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 기존 패턴 변수 찾기
            pattern_regex = r"(\s+)" + pattern_var_name + r"\s*=\s*\[(.*?)\]"
            pattern_match = re.search(pattern_regex, content, re.DOTALL)
            
            if not pattern_match:
                print(f"{pattern_var_name} 변수를 찾을 수 없습니다.")
                return False
            
            # 들여쓰기 추출
            indentation = pattern_match.group(1)
            
            # 새로운 패턴 배열 코드 생성
            subject_patterns_code = pattern_var_name + " = [\n"
            
            # 카테고리별 키워드를 패턴으로 변환
            for category, keywords in keywords_dict.items():
                if keywords:
                    # 카테고리별 주석 추가
                    subject_patterns_code += f"{indentation}    # {category} 카테고리 키워드\n"
                    
                    # 각 키워드를 정규식 OR 연산자(|)로 연결한 패턴 생성
                    pattern = '|'.join([re.escape(kw) for kw in keywords])
                    subject_patterns_code += f"{indentation}    r'{pattern}',\n"
            
            # 기본 의심 패턴 추가
            subject_patterns_code += f"{indentation}    # 기본 의심 패턴\n"
            subject_patterns_code += f"{indentation}    r'(주문|결제).*확인',\n"
            subject_patterns_code += f"{indentation}    r'(지금|즉시).*확인',\n"
            subject_patterns_code += f"{indentation}    r'링크.*클릭',\n"
            subject_patterns_code += f"{indentation}    r'비밀번호|인증|코드'\n"
            subject_patterns_code += f"{indentation}]"
            
            # 패턴 변수 업데이트
            new_content = content[:pattern_match.start()] + indentation + subject_patterns_code + content[pattern_match.end():]
            
            # 원본 파일 내용 업데이트
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"{pattern_var_name} 변수 업데이트 완료")
            return True
        
        except Exception as e:
            print(f"{file_path.name} 파일 업데이트 중 오류: {e}")
            import traceback
            traceback.print_exc()
            return False
    
if __name__ == "__main__":
    root = tk.Tk()
    app = KeywordManager(root)
    root.mainloop()