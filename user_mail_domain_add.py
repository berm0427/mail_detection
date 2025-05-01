import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re
import os
from pathlib import Path

class UserEmailDomainManager:
    def __init__(self, root):
        self.root = root
        self.root.title("유저 이메일 도메인 관리 도구")
        self.root.geometry("700x500")
        
        # 변수 초기화
        self.header_file_path = tk.StringVar()
        self.domains = []
        
        # UI 생성
        self.create_ui()
        
    def create_ui(self):
        # 메인 프레임
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 파일 선택 프레임
        file_frame = ttk.LabelFrame(main_frame, text="헤더 분석기 파일 경로", padding=5)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Entry(file_frame, textvariable=self.header_file_path, width=60).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="찾아보기", command=self.browse_file).pack(side=tk.RIGHT, padx=5)
        ttk.Button(file_frame, text="불러오기", command=self.load_domains).pack(side=tk.RIGHT, padx=5)
        
        # 이메일 도메인 리스트 프레임
        list_frame = ttk.LabelFrame(main_frame, text="유저 이메일 도메인 목록", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 도메인 리스트와 스크롤바
        list_container = ttk.Frame(list_frame)
        list_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.domain_listbox = tk.Listbox(list_container, yscrollcommand=scrollbar.set)
        self.domain_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.domain_listbox.yview)
        
        # 도메인 추가 프레임
        add_frame = ttk.Frame(list_frame)
        add_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.new_domain = tk.StringVar()
        ttk.Label(add_frame, text="새 도메인:").pack(side=tk.LEFT, padx=2)
        ttk.Entry(add_frame, textvariable=self.new_domain).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(add_frame, text="추가", command=self.add_domain).pack(side=tk.LEFT, padx=5)
        ttk.Button(add_frame, text="삭제", command=self.remove_domain).pack(side=tk.LEFT, padx=5)
        
        # 하단 버튼 프레임
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(button_frame, text="저장", command=self.save_domains).pack(side=tk.RIGHT, padx=5)
        
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="헤더 분석기 파일 선택",
            filetypes=[("Python 파일", "*.py"), ("모든 파일", "*.*")]
        )
        
        if file_path:
            self.header_file_path.set(file_path)
            
    def load_domains(self):
        file_path = self.header_file_path.get()
        if not file_path:
            messagebox.showwarning("경고", "헤더 분석기 파일 경로를 선택해주세요.")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("오류", f"파일을 찾을 수 없습니다: {file_path}")
            return
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 첫 번째 위치에서 도메인 추출 (33번줄 근처)
            pattern1 = r'self\.user_email_domains\s*=\s*\[(.*?)\]'
            match1 = re.search(pattern1, content, re.DOTALL)
            
            if match1:
                domains_str = match1.group(1)
                # 문자열에서 도메인 추출
                domains1 = re.findall(r'"([^"]+)"', domains_str)
                
                # 두 번째 위치에서 도메인 추출 (178번줄 근처)
                pattern2 = r'"user":\s*\[(.*?)\]'
                match2 = re.search(pattern2, content, re.DOTALL)
                
                domains2 = []
                if match2:
                    domains_str2 = match2.group(1)
                    domains2 = re.findall(r'"([^"]+)"', domains_str2)
                
                # 두 위치의 도메인 비교
                if set(domains1) != set(domains2):
                    messagebox.showwarning("경고", "두 위치의 도메인 목록이 일치하지 않습니다. 첫 번째 위치의 목록을 사용합니다.")
                
                # 도메인 목록 업데이트
                self.domains = domains1
                self.update_listbox()
                messagebox.showinfo("알림", f"{len(self.domains)}개의 도메인을 불러왔습니다.")
            else:
                messagebox.showerror("오류", "파일에서 유저 이메일 도메인 목록을 찾을 수 없습니다.")
        except Exception as e:
            messagebox.showerror("오류", f"도메인 목록 불러오기 중 오류 발생: {str(e)}")
    
    def update_listbox(self):
        self.domain_listbox.delete(0, tk.END)
        for domain in sorted(self.domains):
            self.domain_listbox.insert(tk.END, domain)
    
    def add_domain(self):
        domain = self.new_domain.get().strip()
        if not domain:
            messagebox.showwarning("경고", "도메인을 입력해주세요.")
            return
            
        # 유효한 도메인 형식인지 확인
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            messagebox.showwarning("경고", "유효한 도메인 형식이 아닙니다.")
            return
            
        if domain in self.domains:
            messagebox.showinfo("알림", f"도메인 '{domain}'은(는) 이미 목록에 있습니다.")
            return
            
        self.domains.append(domain)
        self.update_listbox()
        self.new_domain.set("")  # 입력 필드 초기화
        messagebox.showinfo("알림", f"도메인 '{domain}'이(가) 추가되었습니다.")
    
    def remove_domain(self):
        selected = self.domain_listbox.curselection()
        if not selected:
            messagebox.showwarning("경고", "삭제할 도메인을 선택해주세요.")
            return
            
        domain = self.domain_listbox.get(selected[0])
        
        if messagebox.askyesno("확인", f"도메인 '{domain}'을(를) 삭제하시겠습니까?"):
            self.domains.remove(domain)
            self.update_listbox()
            messagebox.showinfo("알림", f"도메인 '{domain}'이(가) 삭제되었습니다.")
    
    def save_domains(self):
        file_path = self.header_file_path.get()
        if not file_path:
            messagebox.showwarning("경고", "헤더 분석기 파일 경로를 선택해주세요.")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("오류", f"파일을 찾을 수 없습니다: {file_path}")
            return
            
        try:
            # 파일 백업 생성
            backup_path = file_path + '.bak'
            with open(file_path, 'r', encoding='utf-8') as f_in:
                with open(backup_path, 'w', encoding='utf-8') as f_out:
                    f_out.write(f_in.read())
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 첫 번째 위치의 들여쓰기 패턴 찾기
            pattern1 = r'(self\.user_email_domains\s*=\s*\[)(\s*)'
            match1 = re.search(pattern1, content)
            first_indentation = ""
            if match1:
                first_indentation = match1.group(2) or "\n            "
            else:
                first_indentation = "\n            "  # 기본 들여쓰기
                
            # 두 번째 위치의 들여쓰기 패턴 찾기
            pattern2 = r'("user":\s*\[)(\s*)'
            match2 = re.search(pattern2, content)
            second_indentation = ""
            if match2:
                second_indentation = match2.group(2) or "\n                "
            else:
                second_indentation = "\n                "  # 기본 들여쓰기
            
            # 도메인 문자열 생성 (각 위치별 들여쓰기 적용)
            domains_str1 = ""
            for i, domain in enumerate(sorted(self.domains)):
                domains_str1 += f'{first_indentation}"{domain}"'
                if i < len(self.domains) - 1:
                    domains_str1 += ","
                    
            domains_str2 = ""
            for i, domain in enumerate(sorted(self.domains)):
                domains_str2 += f'{second_indentation}"{domain}"'
                if i < len(self.domains) - 1:
                    domains_str2 += ","
            
            # 첫 번째 위치 업데이트 (33번줄 근처)
            pattern1 = r'(self\.user_email_domains\s*=\s*\[)(.*?)(\])'
            replacement1 = f"\\1{domains_str1}{first_indentation}\\3"
            content = re.sub(pattern1, replacement1, content, flags=re.DOTALL)
            
            # 두 번째 위치 업데이트 (178번줄 근처)
            pattern2 = r'("user":\s*\[)(.*?)(\])'
            replacement2 = f"\\1{domains_str2}{second_indentation}\\3"
            content = re.sub(pattern2, replacement2, content, flags=re.DOTALL)
            
            # 파일 저장
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            messagebox.showinfo("알림", f"{len(self.domains)}개의 도메인이 성공적으로 저장되었습니다.\n백업 파일: {backup_path}")
            
        except Exception as e:
            messagebox.showerror("오류", f"도메인 목록 저장 중 오류 발생: {str(e)}")
            import traceback
            traceback.print_exc()
    
if __name__ == "__main__":
    root = tk.Tk()
    app = UserEmailDomainManager(root)
    root.mainloop()