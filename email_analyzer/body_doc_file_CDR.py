import zipfile
import os
import shutil
import sys
from pathlib import Path

def convert_to_zip(doc_path):
    """문서 파일을 .zip 형식으로 변환"""
    zip_path = f"{os.path.splitext(doc_path)[0]}.zip"
    os.rename(doc_path, zip_path)
    return zip_path

def extract_zip(zip_path, extract_dir):
    """ZIP 파일을 지정된 폴더로 압축 해제"""
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

def remove_vba_files(extract_dir):
    """매크로 관련 파일(VBA, BIN 등)을 삭제"""
    vba_found = False
    for root, _, files in os.walk(extract_dir):
        for file in files:
            if file.endswith(('vbaProject.bin', 'vbaData', '.bin')) or 'vba' in file.lower():
                vba_found = True
                file_path = os.path.join(root, file)
                print(f"Removing: {file_path}")
                os.remove(file_path)

    if not vba_found:
        print("No VBA-related files found. File is safe.")

def create_zip_from_folder(folder_path, zip_path):
    """폴더를 ZIP 파일로 압축"""
    shutil.make_archive(zip_path.replace('.zip', ''), 'zip', folder_path)

def convert_back_to_original_format(zip_path, original_doc_path):
    """ZIP 파일을 원래 문서 형식으로 복원"""
    original_extension = os.path.splitext(original_doc_path)[1]
    new_doc_path = f"{os.path.splitext(original_doc_path)[0]}{original_extension}"

    if os.path.exists(new_doc_path):
        os.remove(new_doc_path)  # 기존 파일 삭제
    os.rename(zip_path, new_doc_path)

def clean_up(*paths):
    """임시 파일과 폴더 정리"""
    for path in paths:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.isfile(path):
            os.remove(path)

def process_file(doc_path):
    """CDR 프로세스 실행: 변환, 정화, 재구성"""
    print(f"Processing: {doc_path}")

    # 1. 파일을 ZIP으로 변환
    zip_path = convert_to_zip(doc_path)

    # 2. ZIP 압축 해제
    extract_dir = os.path.splitext(zip_path)[0]
    extract_zip(zip_path, extract_dir)

    # 3. VBA 매크로 파일 삭제
    remove_vba_files(extract_dir)

    # 4. 폴더를 다시 ZIP으로 압축
    create_zip_from_folder(extract_dir, zip_path)

    # 5. ZIP 파일을 원래 문서 형식으로 복원
    convert_back_to_original_format(zip_path, doc_path)

    # 6. 임시 파일과 폴더 정리
    clean_up(zip_path, extract_dir)

    print(f"Finished processing: {doc_path}. Clean and safe!")

if __name__ == "__main__":
    # 명령줄 인자로 파일 경로 받기
    if len(sys.argv) != 2:
        print("Usage: python cdr.py <path_to_doc_or_docx_or_docm>")
        sys.exit(1)

    doc_file = Path(sys.argv[1])

    # 파일 유효성 검사
    if not doc_file.is_file():
        print(f"Error: The specified file does not exist: {doc_file}")
        sys.exit(1)

    # 지원되는 확장자 검사 (.doc, .docx, .docm)
    if doc_file.suffix.lower() not in ['.doc', '.docx', '.docm']:
        print("Error: Please provide a valid .doc, .docx, or .docm file.")
        sys.exit(1)

    # CDR 프로세스 실행
    process_file(str(doc_file))
