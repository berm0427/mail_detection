# body_decoding_v2.py
import os
import sys
import re
import email
import base64
import quopri
import argparse
from email.parser import BytesParser
from email.policy import default
from email.header import decode_header
from pathlib import Path

class EmailBodyDecoder:
    def __init__(self, output_dir="decoded_email"):
        self.output_dir = Path(output_dir)
        self.attachments_dir = self.output_dir / "attachments"
        
    def decode_email(self, email_file, save_attachments=True, view_body=False):
        """이메일 파일을 처리하여 본문과 첨부 파일을 추출합니다."""
        
        # 출력 디렉토리 생성
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.attachments_dir, exist_ok=True)
        
        print(f"출력 디렉토리 생성: {os.path.abspath(self.output_dir)}")
        print(f"첨부 파일 디렉토리 생성: {os.path.abspath(self.attachments_dir)}")
        
        # 이메일 파일 읽기
        with open(email_file, 'rb') as fp:
            print(f"이메일 파일 '{email_file}' 읽는 중...")
            msg = BytesParser(policy=default).parse(fp)
        
        # 메타데이터 추출
        subject = self._decode_str(msg.get('Subject', ''))
        from_addr = self._decode_str(msg.get('From', ''))
        to_addr = self._decode_str(msg.get('To', ''))
        date = self._decode_str(msg.get('Date', ''))
        
        print(f"제목: {subject}")
        print(f"발신자: {from_addr}")
        print(f"수신자: {to_addr}")
        print(f"날짜: {date}")
        
        # 메타데이터 파일 저장
        metadata_path = self.output_dir / "metadata.txt"
        with open(metadata_path, 'w', encoding='utf-8') as f:
            f.write(f"제목: {subject}\n")
            f.write(f"발신자: {from_addr}\n")
            f.write(f"수신자: {to_addr}\n")
            f.write(f"날짜: {date}\n")
        
        print(f"메타데이터 저장 완료: {metadata_path}")
        
        # 본문 추출
        body_html = None
        body_text = None
        
        # 본문 추출 메서드 호출
        body_html, body_text = self._extract_body(msg)
        
        # 본문 저장
        body_path = None
        if body_html:
            body_path = self.output_dir / "decoded_body.html"
            with open(body_path, 'w', encoding='utf-8') as f:
                f.write(body_html)
            print(f"HTML 본문 저장 완료: {body_path}")
        elif body_text:
            body_path = self.output_dir / "decoded_body.txt"
            with open(body_path, 'w', encoding='utf-8') as f:
                f.write(body_text)
            print(f"텍스트 본문 저장 완료: {body_path}")
        else:
            print("본문을 찾을 수 없습니다.")
        
        # 본문 내용 출력 (요청 시)
        if view_body and (body_html or body_text):
            print("\n===== 본문 내용 =====")
            if body_html:
                # HTML 태그 제거
                clean_text = re.sub(r'<[^>]+>', ' ', body_html)
                clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                preview = clean_text[:1000] + "..." if len(clean_text) > 1000 else clean_text
                print(preview)
            else:
                preview = body_text[:1000] + "..." if len(body_text) > 1000 else body_text
                print(preview)
        
        # 첨부 파일 추출
        saved_attachments = []
        
        if save_attachments:
            saved_attachments = self._process_attachments(msg)
            
            # 첨부 파일 요약 메타데이터 추가
            if saved_attachments:
                with open(metadata_path, 'a', encoding='utf-8') as f:
                    f.write(f"\n첨부 파일 ({len(saved_attachments)}개):\n")
                    for i, attachment in enumerate(saved_attachments, 1):
                        f.write(f"  {i}. {attachment['original_name']} ({attachment['size']} 바이트)\n")
        
        # 요약 정보 출력
        print("\n===== 처리 결과 =====")
        print(f"메타데이터: {metadata_path}")
        print(f"본문 파일: {body_path if body_path else '없음'}")
        print(f"첨부 파일: {len(saved_attachments)}개")
        
        for i, attachment in enumerate(saved_attachments, 1):
            print(f"  {i}. {attachment['original_name']} ({attachment['size']} 바이트)")
            print(f"     - 폴더 내 경로: {os.path.basename(attachment['folder_path'])}")
        
        return {
            'metadata_path': metadata_path,
            'body_path': body_path,
            'saved_attachments': saved_attachments
        }

    def _decode_str(self, s):
        """이메일 헤더에서 인코딩된 문자열을 디코딩합니다."""
        if s is None:
            return ""
        
        result = ""
        for part, encoding in decode_header(s):
            if isinstance(part, bytes):
                if encoding:
                    try:
                        result += part.decode(encoding)
                    except:
                        result += part.decode('utf-8', errors='replace')
                else:
                    result += part.decode('utf-8', errors='replace')
            else:
                result += part
        return result

    def _extract_body(self, msg_part):
        """이메일에서 본문 텍스트와 HTML을 추출합니다."""
        body_html = None
        body_text = None
        
        if msg_part.is_multipart():
            # 멀티파트 메시지면 각 파트를 재귀적으로 처리
            for part in msg_part.get_payload():
                html, text = self._extract_body(part)
                if html and not body_html:
                    body_html = html
                if text and not body_text:
                    body_text = text
        else:
            content_type = msg_part.get_content_type()
            content_disposition = msg_part.get_content_disposition()
            
            # Content-Disposition이 없거나 inline인 경우만 본문으로 간주
            if content_disposition is None or content_disposition == 'inline':
                if content_type == 'text/html':
                    body_html = msg_part.get_content()
                elif content_type == 'text/plain':
                    body_text = msg_part.get_content()
        
        return body_html, body_text

    def _process_attachments(self, msg_part):
        """이메일 첨부 파일을 추출하여 저장합니다."""
        saved_attachments = []
        
        def _process_part(part):
            if part.is_multipart():
                # 멀티파트 메시지면 각 파트를 재귀적으로 처리
                for subpart in part.get_payload():
                    _process_part(subpart)
            else:
                content_disposition = part.get_content_disposition()
                filename = part.get_filename()
                
                # 첨부 파일 조건 확인
                is_attachment = False
                
                # 1. Content-Disposition이 attachment인 경우
                if content_disposition and 'attachment' in content_disposition:
                    is_attachment = True
                # 2. 파일명이 있는 경우
                elif filename:
                    is_attachment = True
                # 3. application/ 타입인 경우
                elif part.get_content_type().startswith('application/'):
                    is_attachment = True
                    filename = filename or f"attachment_{len(saved_attachments)+1}"
                
                if is_attachment and filename:
                    # 파일명 디코딩
                    filename = self._decode_str(filename)
                    print(f"첨부 파일 발견: {filename}")
                    
                    # 데이터 추출
                    payload = part.get_payload(decode=True)
                    
                    if payload:
                        # 안전한 파일명 만들기
                        safe_filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
                        
                        # 첨부 파일 디렉토리에 저장
                        attachment_path = self.attachments_dir / safe_filename
                        counter = 1
                        while os.path.exists(attachment_path):
                            name, ext = os.path.splitext(safe_filename)
                            attachment_path = self.attachments_dir / f"{name}_{counter}{ext}"
                            counter += 1
                        
                        try:
                            with open(attachment_path, 'wb') as f:
                                f.write(payload)
                            print(f"첨부 파일 폴더 내 저장 성공: {attachment_path}")
                            
                            # 저장 정보 기록
                            saved_attachments.append({
                                'original_name': filename,
                                'folder_path': str(attachment_path),
                                'size': len(payload)
                            })
                            
                        except Exception as e:
                            print(f"첨부 파일 '{filename}' 저장 오류: {e}")
        
        # 첨부 파일 처리 실행
        _process_part(msg_part)
        return saved_attachments

def main():
    parser = argparse.ArgumentParser(description='이메일 파일에서 본문과 첨부 파일을 추출합니다.')
    parser.add_argument('email_file', help='이메일 파일 경로')
    parser.add_argument('-o', '--output', help='출력 디렉토리 (기본: decoded_email)', default='decoded_email')
    parser.add_argument('-v', '--view', action='store_true', help='본문 내용을 콘솔에 출력')
    parser.add_argument('-n', '--no-attachments', action='store_true', help='첨부 파일을 저장하지 않음')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.email_file):
        print(f"오류: 파일 '{args.email_file}'이 존재하지 않습니다.")
        sys.exit(1)
    
    try:
        print(f"\n===== 이메일 파일 '{args.email_file}' 처리 시작 =====\n")
        decoder = EmailBodyDecoder(args.output)
        result = decoder.decode_email(
            args.email_file, 
            save_attachments=not args.no_attachments,
            view_body=args.view
        )
        
        if result['saved_attachments']:
            print(f"\n성공: {len(result['saved_attachments'])}개의 첨부 파일이 저장되었습니다.")
        elif not args.no_attachments:
            print("\n알림: 이메일에 첨부 파일이 없거나 추출할 수 없습니다.")
        
        print(f"\n모든 처리가 '{os.path.abspath(args.output)}' 디렉토리에 완료되었습니다.")
        
    except Exception as e:
        print(f"\n오류 발생: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()