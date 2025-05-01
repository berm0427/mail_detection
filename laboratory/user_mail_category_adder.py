import sys
import re
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QTableWidget, QTableWidgetItem, QMessageBox, 
                            QGroupBox, QFormLayout, QFileDialog, QHeaderView)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import os
import json

class CategoryCheckManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.categories = []
        self.file_path = None
        self.load_default_categories()
        
    def initUI(self):
        self.setWindowTitle('이메일 분석 카테고리 검사 관리')
        self.setGeometry(100, 100, 800, 600)
        
        # 메인 위젯과 레이아웃
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        
        # 카테고리 관리 섹션
        category_group = QGroupBox("카테고리 검사 관리")
        category_layout = QVBoxLayout()
        
        # 안내 레이블
        guide_label = QLabel("이 도구는 integration.py 파일에서 사용자 계정의 기관 사칭을 검사하는 카테고리를 관리합니다.")
        guide_label.setWordWrap(True)
        category_layout.addWidget(guide_label)
        
        # 카테고리 목록 테이블
        self.category_table = QTableWidget()
        self.category_table.setColumnCount(2)
        self.category_table.setHorizontalHeaderLabels(["카테고리 이름", "변수명"])
        self.category_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.category_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        category_layout.addWidget(self.category_table)
        
        # 카테고리 추가 섹션
        add_layout = QHBoxLayout()
        
        # 카테고리 이름 입력
        name_layout = QVBoxLayout()
        name_label = QLabel("카테고리 이름:")
        self.category_name_input = QLineEdit()
        self.category_name_input.setPlaceholderText("예: education, medical 등")
        name_layout.addWidget(name_label)
        name_layout.addWidget(self.category_name_input)
        add_layout.addLayout(name_layout)
        
        # 변수명 입력
        var_layout = QVBoxLayout()
        var_label = QLabel("변수명:")
        self.var_name_input = QLineEdit()
        self.var_name_input.setPlaceholderText("예: edu_count, med_count 등")
        var_layout.addWidget(var_label)
        var_layout.addWidget(self.var_name_input)
        add_layout.addLayout(var_layout)
        
        # 추가 버튼
        add_button = QPushButton("추가")
        add_button.clicked.connect(self.add_category)
        add_layout.addWidget(add_button)
        
        category_layout.addLayout(add_layout)
        
        # 삭제 버튼
        delete_button = QPushButton("선택한 카테고리 삭제")
        delete_button.clicked.connect(self.delete_category)
        category_layout.addWidget(delete_button)
        
        category_group.setLayout(category_layout)
        main_layout.addWidget(category_group)
        
        # 파일 작업 (저장/불러오기)
        file_ops_layout = QHBoxLayout()
        
        save_button = QPushButton("저장")
        save_button.clicked.connect(self.save_categories)
        
        save_as_button = QPushButton("다른 이름으로 저장")
        save_as_button.clicked.connect(self.save_categories_as)
        
        load_button = QPushButton("불러오기")
        load_button.clicked.connect(self.load_categories)
        
        generate_button = QPushButton("코드 생성")
        generate_button.clicked.connect(self.generate_code)
        
        file_ops_layout.addWidget(save_button)
        file_ops_layout.addWidget(save_as_button)
        file_ops_layout.addWidget(load_button)
        file_ops_layout.addWidget(generate_button)
        
        main_layout.addLayout(file_ops_layout)
        
        # 생성된 코드 미리보기
        preview_group = QGroupBox("코드 미리보기")
        preview_layout = QVBoxLayout()
        
        self.code_preview = QLabel()
        self.code_preview.setStyleSheet("background-color: #f0f0f0; padding: 10px; font-family: Courier, monospace;")
        self.code_preview.setWordWrap(True)
        self.code_preview.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.code_preview.setText("카테고리를 추가하면 여기에 코드가 생성됩니다.")
        
        preview_layout.addWidget(self.code_preview)
        preview_group.setLayout(preview_layout)
        main_layout.addWidget(preview_group)
        
        # 상태 바
        self.statusBar().showMessage('준비됨')
        
        # 메인 위젯 설정
        self.setCentralWidget(main_widget)
    
    def load_default_categories(self):
        """기본 카테고리 로드"""
        self.categories = [
            {"name": "investigation", "var_name": "inv_count"},
            {"name": "government", "var_name": "gov_count"},
            {"name": "financial", "var_name": "fin_count"},
            {"name": "education", "var_name": "edu_count"},
            {"name": "military", "var_name": "mil_count"},
            {"name": "delivery", "var_name": "del_count"}
        ]
        self.update_category_table()
        self.update_code_preview()
    
    def update_category_table(self):
        """카테고리 테이블 업데이트"""
        self.category_table.setRowCount(len(self.categories))
        for i, category in enumerate(self.categories):
            self.category_table.setItem(i, 0, QTableWidgetItem(category["name"]))
            self.category_table.setItem(i, 1, QTableWidgetItem(category["var_name"]))
    
    def add_category(self):
        """새 카테고리 추가"""
        category_name = self.category_name_input.text().strip()
        var_name = self.var_name_input.text().strip()
        
        if not category_name:
            QMessageBox.warning(self, "입력 오류", "카테고리 이름을 입력하세요.")
            return
        
        if not var_name:
            QMessageBox.warning(self, "입력 오류", "변수명을 입력하세요.")
            return
        
        # 중복 확인
        for category in self.categories:
            if category["name"] == category_name:
                QMessageBox.warning(self, "중복", f"카테고리 '{category_name}'이(가) 이미 존재합니다.")
                return
        
        self.categories.append({"name": category_name, "var_name": var_name})
        self.update_category_table()
        self.update_code_preview()
        
        # 입력 필드 초기화
        self.category_name_input.clear()
        self.var_name_input.clear()
    
    def delete_category(self):
        """선택된 카테고리 삭제"""
        selected_rows = set(index.row() for index in self.category_table.selectedIndexes())
        if not selected_rows:
            QMessageBox.warning(self, "선택 오류", "삭제할 카테고리를 선택하세요.")
            return
        
        # 역순으로 삭제하여 인덱스 변화 방지
        for row in sorted(selected_rows, reverse=True):
            del self.categories[row]
        
        self.update_category_table()
        self.update_code_preview()
    
    def update_code_preview(self):
        """코드 미리보기 업데이트"""
        if not self.categories:
            self.code_preview.setText("카테고리를 추가하면 여기에 코드가 생성됩니다.")
            return
        
        code = "# integration.py 파일에 추가할 코드:\n\n"
        code += "# header_result.get('organization_type') == 'user': 다음에 추가할 코드\n"
        
        # 변수 선언 생성
        for category in self.categories:
            code += f"                {category['var_name']} = body_result.get('categories', {{}}).get('{category['name']}', {{}}).get('count', 0)\n"
        
        code += "\n                # 모든 카테고리 조합에 대한 사칭 검사\n"
        code += "                if "
        
        # 조건문 생성
        conditions = []
        for category in self.categories:
            conditions.append(f"{category['var_name']} > 0")
        
        code += " or ".join(conditions)
        
        # 코드 블록 완성
        code += ":\n"
        code += "                    impersonation_score = 40  # 높은 가중치\n"
        code += "                    risk_score += impersonation_score\n"
        code += '                    reasons.append(f"사용자 계정의 기관 사칭 의심: +{impersonation_score}")\n'
        code += '                    logger.warning("사용자 계정에서 기관 사칭 의심 발견")\n'
        
        self.code_preview.setText(code)
    
    def save_categories(self):
        """현재 파일에 카테고리 저장 또는 새 파일 요청"""
        if not self.file_path:
            self.save_categories_as()
        else:
            self.save_to_file(self.file_path)
    
    def save_categories_as(self):
        """새 파일에 카테고리 저장"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "카테고리 저장", "", "JSON 파일 (*.json);;모든 파일 (*)"
        )
        if file_path:
            self.save_to_file(file_path)
    
    def save_to_file(self, file_path):
        """지정된 파일에 카테고리 저장"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.categories, f, ensure_ascii=False, indent=4)
            self.file_path = file_path
            self.statusBar().showMessage(f'{file_path}에 저장됨', 3000)
        except Exception as e:
            QMessageBox.critical(self, "저장 오류", f"파일 저장 중 오류 발생: {str(e)}")
    
    def load_categories(self):
        """파일에서 카테고리 불러오기"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "카테고리 불러오기", "", "JSON 파일 (*.json);;모든 파일 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.categories = json.load(f)
                self.update_category_table()
                self.update_code_preview()
                self.file_path = file_path
                self.statusBar().showMessage(f'{file_path}에서 불러옴', 3000)
            except Exception as e:
                QMessageBox.critical(self, "불러오기 오류", f"파일 불러오기 중 오류 발생: {str(e)}")
    
    def generate_code(self):
        """integration.py용 코드 생성"""
        if not self.categories:
            QMessageBox.warning(self, "빈 카테고리", "정의된 카테고리가 없습니다.")
            return
        
        code = self.code_preview.text()
        
        # 대화상자에 표시하고 복사 옵션 제공
        dialog = QMessageBox(self)
        dialog.setWindowTitle("생성된 코드")
        dialog.setText("이 코드를 복사하여 integration.py 파일에 붙여넣으세요:")
        dialog.setDetailedText(code)
        dialog.setStandardButtons(QMessageBox.Ok | QMessageBox.Save)
        
        result = dialog.exec_()
        if result == QMessageBox.Save:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "생성된 코드 저장", "", "Python 파일 (*.py);;텍스트 파일 (*.txt);;모든 파일 (*)"
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(code)
                    self.statusBar().showMessage(f'코드가 {file_path}에 저장됨', 3000)
                except Exception as e:
                    QMessageBox.critical(self, "저장 오류", f"파일 저장 중 오류 발생: {str(e)}")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # 모든 플랫폼에서 일관된 모던한 스타일
    window = CategoryCheckManager()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()