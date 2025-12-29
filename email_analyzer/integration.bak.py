# email_analyzer/integration.py
import os
import logging
import json
import uuid
import re
from pathlib import Path
from datetime import datetime
import traceback
from email import policy
from email.parser import BytesParser
from email.header import decode_header

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("anthropic 라이브러리를 찾을 수 없습니다. Claude AI 분석 기능이 비활성화됩니다.")

try:
    from config import ANTHROPIC_API_KEY, AI_ENABLED, AI_MODEL
except ImportError:
    logger.warning("config.py 파일을 찾을 수 없습니다.")

# 프로젝트 루트 경로 추가
import sys
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# 헤더 분석기 가져오기 (정확한 경로)
try:
    # 수정된 경로: mail_header 디렉토리 내의 모듈
    from mail_header.mail_header_detection_v4 import EmailHeaderAnalyzer
    logger.info("헤더 분석기 임포트 성공")
except ImportError as e:
    logger.error(f"헤더 분석기 임포트 실패: {e}")
    # 파일 존재 여부 확인 - 정확한 경로 사용
    header_file = project_root / 'mail_header' / 'mail_header_detection_v4.py'
    logger.error(f"헤더 파일 존재 여부: {header_file.exists()}")
    raise

# 본문 분석기 가져오기
from email_analyzer.body_analyzer import BodyAnalyzer

class IntegratedAnalyzer:
    """통합 이메일 분석기"""
    
    def __init__(self, keywords_dir, result_dir=None, attachments_dir=None):
        self.header_analyzer = EmailHeaderAnalyzer()
        self.body_analyzer = BodyAnalyzer(keywords_dir)
        self.user_email_domains = self.header_analyzer.user_email_domains
        self.result_dir = Path(result_dir) if result_dir else Path("analysis_result")
        self.attachments_dir = Path(attachments_dir) if attachments_dir else self.result_dir / "attachments"
        
        # 결과 저장 디렉토리 생성
        os.makedirs(self.result_dir, exist_ok=True)
        os.makedirs(self.attachments_dir, exist_ok=True)
    
    def analyze_with_claude(self, email_data, initial_analysis):
        """Claude AI로 이메일 추가 분석"""
        try:
            if not AI_ENABLED or not ANTHROPIC_AVAILABLE or not ANTHROPIC_API_KEY:
                logger.info("AI 분석이 비활성화되어 있거나 필요한 설정이 없습니다.")
                return None
            
            # API 클라이언트 설정
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            
            # 첨부 파일 정보 포맷팅
            attachments_info = "없음"
            if initial_analysis.get('attachments'):
                attachments_info = "\n".join([
                    f"- {att['filename']} ({self._format_file_size(att['size'])})"
                    for att in initial_analysis['attachments']
                ])
            
            # 위험 요소 포맷팅
            risk_factors = "없음"
            if initial_analysis.get('reasons'):
                risk_factors = "\n".join([f"- {reason}" for reason in initial_analysis['reasons']])
            
            # 프롬프트 구성 (더 나은 프롬프트가 있으면 수정하셔도 됩니다)
            prompt = f"""
            당신은 이메일 보안 전문가입니다. 다음 이메일이 피싱, 스팸, 사기 또는 기타 악성 시도인지 분석해주세요.

            ## 이메일 정보
            제목: {email_data.get('subject', 'N/A')}
            발신자: {email_data.get('from', 'N/A')}
            발신 도메인: {initial_analysis['header'].get('sender_domain', 'N/A')}

            ## 이메일 본문
            {email_data.get('body', '')[:3000]}

            ## 첨부 파일
            {attachments_info}

            ## 기본 분석 결과
            위험도 점수: {initial_analysis['risk_score']}/100
            도메인 평판: {initial_analysis['header'].get('domain_reputation', 'unknown')}
            SPF 검증: {initial_analysis['header'].get('spf_check', 'unknown')}
            DKIM 검증: {initial_analysis['header'].get('dkim_check', 'unknown')}
            DMARC 검증: {initial_analysis['header'].get('dmarc_check', 'unknown')}
            도메인 나이: {initial_analysis.get('domain_age_days', 'unknown')}일

            ## 감지된 위험 요소
            {risk_factors}

            ## 중요 고려사항
            - 도메인이 .go.kr, .or.kr, .kr 등 한국 공식 기관 또는 회사 도메인이고, 등록된 지 1년 이상이면 높은 신뢰성을 가진 것으로 간주하세요.
            - 한국의 많은 정상적인 기업이나 서비스에서는 DKIM이나 DMARC가 구현되지 않은 경우가 흔합니다. SPF만 통과해도 기본적인 인증은 충족된 것으로 볼 수 있습니다.
            - 로그인 알림, 비밀번호 재설정, 계정 확인 등은 정상적인 서비스에서도 자주 보내는 메시지입니다.

            ## 사칭 감지 및 우선순위 지정
            - 공공 기관(경찰, 검찰, 법원, 국세청 등)을 사칭하면서 개인 이메일 서비스(gmail.com, kakao.com, naver.com 등)를 사용하는 경우, 다른 모든 요소보다 이것을 최우선 위험 신호로 간주하세요.
            - 이런 경우 도메인 신뢰성이나 SPF/DKIM 인증 통과 여부와 상관없이 위험도는 최소 80점 이상이어야 합니다.
            - 발신 도메인이 오래되었고 인증(SPF/DKIM)에 통과했더라도, 내용상 명백한 사칭이 있다면 이러한 긍정적 요소들이 위험도를 낮추는 데 영향을 미치지 않아야 합니다.
            - 사칭 행위는 어떤 기술적 인증보다 항상 우선시되어야 합니다.

            ## 이메일 평가 방법

            - 도메인 신뢰성: 오래된 도메인(.kr, .com 등)이 최근 생성된 도메인보다 신뢰성이 높습니다.
            - 이메일 인증: 한국 서비스의 경우 SPF 통과만으로도 기본적인 발신자 검증은 된 것으로 볼 수 있습니다.
            - 본문 내용: 급한 행동 촉구, (이미지 내의 src 태그에 URL이 숨겨있는 경우는 숨겨진 것도 확인) 악성 URL 여부, 비정상적인 개인정보 요구, 문법/맞춤법 오류가 많은지 확인하세요.
            - 악성 URL 특징은 (IP 주소 직접 사용, 의심스러운 최상위 도메인(.tk, .ml, .ga, .cf, .gq, .pw, .top, .click, .download 등), 과도하게 긴 서브도메인(4개 이상), URL 단축 서비스 사용, 브랜드 사칭 키워드(secure-bank, login-paypal 등), 과도한 하이픈 사용(3개 이상 연속), 도메인에 5자리 이상 숫자 패턴, 유명 브랜드명 뒤 추가 문자(naver-abc123.com 등), 과도하게 긴 URL(150자 이상), 리다이렉션 파라미터(redirect=, url= 등), 혼동 문자 연속 사용(1l0O 등 3개 이상), 한글 도메인 피싱, 비표준 포트 사용, 클라우드 스토리지 남용, 긴 해시값(30자 이상), 랜덤 문자열 경로, 의심스러운 파일명 등의 특징을 보임)[1][2][3]
            - 링크 및 첨부 파일: 이메일의 목적과 일치하는지 확인하세요.


            ## 분석 가이드라인
            - 위험도 평가는 도메인 신뢰성(40%) > 본문 내용과 요구하는 행동(30%) > 헤더 인증(20%) > 기타 요소(10%) 순으로 가중치를 두세요.
            - 오래된 도메인에서 발송되고 SPF가 통과한 이메일은 DKIM이나 DMARC가 실패하더라도 크게 의심하지 마세요.
            - 특히 한국 서비스/기업의 경우 DKIM/DMARC 실패만으로 위험도를 크게 높이지 마세요.

            ## 분석 질문
            1. 이 이메일은 악성일 가능성이 얼마나 됩니까? (0-100점)
            2. 가장 의심스러운 요소는 무엇입니까?
            3. 발신자가 자신을 위장하고 있는 징후가 있습니까?
            4. 이메일 본문에서 심리적 조작 전술이 사용되고 있습니까?
            5. 이메일이 수신자에게 어떤 행동을 유도하려고 합니까?
            6. 보안 관점에서 이메일에 대한 최종 평가는 무엇입니까?

            ## 추가 질문
            1. 이 서비스/기업의 일반적인 커뮤니케이션 패턴과 일치하나요?
            2. 도메인이 5년 이상 된 경우, DKIM/DMARC 실패가 위험도에 얼마나 영향을 미쳐야 하나요?
            3. 이메일에서 요구하는 행동이 해당 서비스의 일반적인 프로세스와 일치하나요?

            JSON 형식으로 응답해주세요. 다음과 같은 필드를 포함해야 합니다:
            - risk_score: 0-100 사이의 숫자 (한국 서비스의 경우 DKIM/DMARC 실패만으로는 점수를 20점 이상 올리지 마세요)
            - verdict: "안전", "의심", "위험" 중 하나
            - suspicious_elements: 의심스러운 요소 목록
            - explanation: 이메일이 악성인 이유 또는 안전한 이유에 대한 설명
            - recommendation: 사용자에게 제안하는 행동 지침
            """
            
            logger.info("Claude API에 분석 요청 중...")
            
            # Claude API 호출
            response = client.messages.create(
                model=AI_MODEL,
                max_tokens=2000,
                temperature=0.0,
                system="당신은 이메일 보안 분석 전문가로, JSON 형식으로 명확한 분석 결과를 제공합니다.",
                messages=[{"role": "user", "content": prompt}]
            )
            
            # 응답 객체 디버깅
            logger.info(f"응답 객체 타입: {type(response)}")
            logger.info(f"응답 객체 속성: {dir(response)}")
            
            # JSON 응답 추출 및 파싱
            ai_result = None
            error_msg = ""
            
            try:
                content = ""
                
                # 응답의 content 직접 확인 (새 API 버전)
                if hasattr(response, 'content'):
                    logger.info(f"response.content 타입: {type(response.content)}")
                    
                    # 문자열인 경우
                    if isinstance(response.content, str):
                        content = response.content
                        logger.info(f"문자열 content 길이: {len(content)}")
                    # 리스트인 경우
                    elif isinstance(response.content, list):
                        logger.info(f"리스트 content 길이: {len(response.content)}")
                        for i, item in enumerate(response.content):
                            logger.info(f"항목 {i} 타입: {type(item)}")
                            
                            # TextBlock 객체 처리
                            if hasattr(item, 'text'):
                                content = item.text
                                logger.info(f"TextBlock에서 텍스트 추출 성공, 길이: {len(content)}")
                                break
                            # 딕셔너리 처리
                            elif isinstance(item, dict):
                                logger.info(f"항목 {i} 키: {item.keys()}")
                                if 'text' in item:
                                    content = item['text']
                                    logger.info(f"딕셔너리에서 텍스트 추출 성공, 길이: {len(content)}")
                                    break
                                elif 'type' in item and item['type'] == 'text':
                                    content = item.get('value', '')
                                    logger.info(f"텍스트 타입 항목에서 추출 성공, 길이: {len(content)}")
                                    break
                        
                        if not content:
                            # 모델 타입 객체를 직접 변환하려고 시도
                            try:
                                if hasattr(response.content[0], 'model_dump'):
                                    dump = response.content[0].model_dump()
                                    if 'text' in dump:
                                        content = dump['text']
                                        logger.info(f"모델 덤프에서 텍스트 추출 성공, 길이: {len(content)}")
                            except Exception as e:
                                logger.warning(f"모델 덤프 추출 실패: {str(e)}")
                                
                            if not content:
                                content = str(response.content)
                                logger.info("리스트에서 텍스트 추출 실패, 전체 변환")
                    else:
                        content = str(response.content)
                        logger.info(f"기타 타입 content를 문자열로 변환, 길이: {len(content)}")
                
                # 응답 객체 직접 변환 시도
                elif hasattr(response, 'model_dump'):
                    try:
                        dump = response.model_dump()
                        logger.info(f"model_dump 결과: {dump.keys() if isinstance(dump, dict) else 'Not a dict'}")
                        
                        if isinstance(dump, dict) and 'content' in dump:
                            content_data = dump['content']
                            
                            if isinstance(content_data, list):
                                for item in content_data:
                                    if isinstance(item, dict):
                                        if 'text' in item:
                                            content = item['text']
                                            logger.info(f"model_dump 리스트에서 텍스트 추출, 길이: {len(content)}")
                                            break
                            elif isinstance(content_data, str):
                                content = content_data
                                logger.info(f"model_dump에서 문자열 추출, 길이: {len(content)}")
                    except Exception as e:
                        logger.warning(f"model_dump 처리 오류: {str(e)}")
                
                # 마지막 수단으로 응답 객체를 문자열로 변환
                if not content:
                    try:
                        content = str(response)
                        logger.info(f"응답 객체를 문자열로 변환, 길이: {len(content)}")
                    except:
                        content = ""
                        logger.warning("응답 객체를 문자열로 변환 실패")
                        
                # 내용에서 JSON 찾기
                if content:
                    # 코드 블록에서 JSON 찾기
                    json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', content, re.DOTALL)
                    if json_match:
                        json_text = json_match.group(1).strip()
                        try:
                            ai_result = json.loads(json_text)
                            logger.info("JSON 코드 블록에서 결과 추출 성공")
                        except json.JSONDecodeError as e:
                            error_msg = f"JSON 블록 파싱 오류: {str(e)}"
                            logger.warning(error_msg)
                    
                    # 직접 JSON 객체 찾기
                    if not ai_result:
                        json_match = re.search(r'({[\s\S]*?})', content, re.DOTALL)
                        if json_match:
                            json_text = json_match.group(1).strip()
                            try:
                                ai_result = json.loads(json_text)
                                logger.info("일반 텍스트에서 JSON 객체 추출 성공")
                            except json.JSONDecodeError:
                                # 더 관대한 방식으로 다시 시도
                                try:
                                    # 키를 따옴표로 감싸기
                                    fixed_json = re.sub(r'(\w+):', r'"\1":', json_text)
                                    ai_result = json.loads(fixed_json)
                                    logger.info("수정된 JSON 추출 성공")
                                except json.JSONDecodeError as e:
                                    error_msg = f"JSON 파싱 오류: {str(e)}"
                                    logger.warning(error_msg)
                else:
                    logger.warning("응답에서 내용을 추출할 수 없습니다")
                    error_msg = "응답에서 내용을 추출할 수 없습니다"
            
            except Exception as e:
                error_msg = f"응답 처리 중 오류: {str(e)}"
                logger.error(error_msg)
                logger.error(traceback.format_exc())
            
            # AI 결과가 없는 경우 기본 실패 메시지 제공
            if not ai_result:
                logger.warning(f"AI 응답 처리 실패: {error_msg}")
                
                # 간단한 실패 메시지 제공
                ai_result = {
                    "risk_score": 0,
                    "verdict": "분석 실패",
                    "suspicious_elements": [],
                    "explanation": f"AI 분석 중 오류가 발생했습니다: {error_msg}",
                    "recommendation": "기본 분석 결과를 참고하세요."
                }
            
            # AI 분석 결과 저장
            result_path = self.result_dir / "ai_analysis_result.json"
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(ai_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"AI 분석 완료: 위험도 {ai_result.get('risk_score')}/100, 판정: {ai_result.get('verdict')}")
            
            return ai_result
            
        except Exception as e:
            logger.error(f"Claude API 분석 중 오류 발생: {e}")
            logger.error(traceback.format_exc())
            return {
                "risk_score": 0,
                "verdict": "분석 실패",
                "suspicious_elements": [],
                "explanation": f"AI 분석 중 오류 발생: {str(e)}",
                "recommendation": "기본 분석 결과를 참고하세요."
            }
    
    def _format_file_size(self, size_in_bytes):
        """파일 크기를 읽기 쉬운 형식으로 변환"""
        if size_in_bytes > 1048576:  # 1MB
            return f"{size_in_bytes/1048576:.2f} MB"
        elif size_in_bytes > 1024:  # 1KB
            return f"{size_in_bytes/1024:.1f} KB"
        else:
            return f"{size_in_bytes} 바이트"
    
    
    def parse_email(self, email_path):
        """이메일 파일 파싱"""
        try:
            logger.info(f"\n==== 이메일 분석 시작: {email_path} ====")
            
            # 세션 ID 생성 (결과 디렉토리 이름에서 추출)
            self.session_id = self.result_dir.name
            logger.info(f"출력 디렉토리 생성: {self.result_dir}")
            logger.info(f"첨부 파일 디렉토리 생성: {self.attachments_dir}")
            
            with open(email_path, 'rb') as f:
                raw_email = f.read()
                
            logger.info(f"이메일 파일 '{email_path}' 읽는 중...")
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            # 기본 메타데이터 추출
            subject = msg.get('Subject', '')
            if subject:
                # 인코딩된 제목 디코딩
                decoded_parts = []
                for part, encoding in decode_header(subject):
                    if isinstance(part, bytes):
                        if encoding:
                            try:
                                decoded_parts.append(part.decode(encoding))
                            except:
                                decoded_parts.append(part.decode('utf-8', errors='replace'))
                        else:
                            decoded_parts.append(part.decode('utf-8', errors='replace'))
                    else:
                        decoded_parts.append(part)
                subject = ''.join(decoded_parts)
            
            from_header = msg.get('From', '')
            to_header = msg.get('To', '')
            date_header = msg.get('Date', '')
            
            logger.info(f"제목: {subject}")
            logger.info(f"발신자: {from_header}")
            logger.info(f"수신자: {to_header}")
            logger.info(f"날짜: {date_header}")
            
            # 메타데이터 저장
            metadata_path = self.result_dir / "metadata.txt"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                f.write(f"Subject: {subject}\n")
                f.write(f"From: {from_header}\n")
                f.write(f"To: {to_header}\n")
                f.write(f"Date: {date_header}\n")
                f.write("\nHeaders:\n")
                for name, value in msg.items():
                    f.write(f"{name}: {value}\n")
            
            logger.info(f"메타데이터 저장 완료: {metadata_path}")
            
            # 본문 추출 및 저장
            body = self.get_email_body(msg)
            body_path = self.result_dir / "decoded_body.html"
            with open(body_path, 'w', encoding='utf-8') as f:
                f.write(body)
            logger.info(f"HTML 본문 저장 완료: {body_path}")
            
            # 첨부 파일 처리
            attachments = []
            for part in msg.iter_attachments():
                filename = part.get_filename()
                if filename:
                    # 첨부 파일 이름에서 위험한 문자 제거
                    safe_filename = re.sub(r'[^\w\.-]', '_', filename)
                    
                    # 첨부 파일 저장 경로 설정
                    attachment_path = self.attachments_dir / safe_filename
                    
                    # 이미 존재하면 고유한 이름으로 변경
                    if attachment_path.exists():
                        name, ext = os.path.splitext(safe_filename)
                        safe_filename = f"{name}_{uuid.uuid4().hex[:6]}{ext}"
                        attachment_path = self.attachments_dir / safe_filename
                    
                    # 첨부 파일 저장
                    with open(attachment_path, 'wb') as f:
                        f.write(part.get_payload(decode=True))
                    
                    logger.info(f"첨부 파일 발견: {filename}")
                    logger.info(f"첨부 파일 저장 완료: {attachment_path}")
                    
                    # 첨부 파일 정보 저장
                    attachments.append({
                        'filename': filename,
                        'size': os.path.getsize(attachment_path),
                        'path': str(attachment_path.relative_to(self.result_dir.parent.parent))
                    })
            
            # 처리 결과 로깅
            logger.info("\n===== 처리 결과 =====")
            logger.info(f"메타데이터: {metadata_path}")
            logger.info(f"본문 파일: {body_path}")
            logger.info(f"첨부 파일: {len(attachments)}개")
            for i, att in enumerate(attachments, 1):
                logger.info(f"  {i}. {att['filename']} ({att['size']} 바이트)")
                logger.info(f"     - 저장 경로: {att['path']}")
            
            return {
                'msg': msg,
                'subject': subject,
                'body': body,
                'attachments': attachments,
                'raw_email': raw_email
            }
            
        except Exception as e:
            logger.error(f"이메일 파싱 오류: {e}")
            raise
    
    def get_email_body(self, msg):
        """이메일 본문 추출 (HTML 우선)"""
        body = ""
        
        # HTML 본문 우선 추출
        if msg.is_multipart():
            for part in msg.get_payload():
                if part.get_content_type() == 'text/html':
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                    return body
            
            # HTML이 없으면 일반 텍스트 추출
            for part in msg.get_payload():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                    # 텍스트를 HTML로 변환
                    body = f"<html><head><meta charset='utf-8'></head><body><pre>{body}</pre></body></html>"
                    return body
        else:
            # 단일 파트 메시지
            content_type = msg.get_content_type()
            if content_type == 'text/html':
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
            elif content_type == 'text/plain':
                text = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                body = f"<html><head><meta charset='utf-8'></head><body><pre>{text}</pre></body></html>"
        
        return body
    
    def extract_text_from_html(self, html):
        """HTML에서 텍스트 추출 - 개선된 버전"""
        try:
            # 일부 HTML 문서에서는 내용이 비어 있거나 극히 짧을 수 있음
            if not html or len(html) < 10:
                logger.warning("HTML 내용이 비어 있거나 너무 짧습니다.")
                return ""
                
            # 기본 HTML 태그 제거
            text = re.sub(r'<[^>]+>', ' ', html)
            text = re.sub(r'\s+', ' ', text).strip()
            
            # 텍스트가 너무 짧은 경우, 원본 HTML에서 텍스트 추출 시도
            if len(text) < 10:
                logger.info("기본 방식으로 추출한 텍스트가 너무 짧아 대체 방법 시도")
                # href, span, div 내용 추출 시도
                href_texts = re.findall(r'href="([^"]+)"', html)
                span_texts = re.findall(r'<span[^>]*>([^<]+)</span>', html)
                div_texts = re.findall(r'<div[^>]*>([^<]+)</div>', html)
                
                # 제목에서 키워드 추출
                subject = self.current_email_subject if hasattr(self, 'current_email_subject') else ""
                
                # 모든 텍스트 조합
                all_texts = []
                if subject:
                    all_texts.append(subject)
                all_texts.extend(href_texts)
                all_texts.extend(span_texts)
                all_texts.extend(div_texts)
                
                # 텍스트 정제
                all_texts = [t for t in all_texts if len(t) > 3]  # 너무 짧은 텍스트 제외
                text = ' '.join(all_texts)
                
            # 엔티티 디코딩
            text = text.replace('&nbsp;', ' ')
            text = text.replace('&amp;', '&')
            text = text.replace('&lt;', '<')
            text = text.replace('&gt;', '>')
            text = text.replace('&quot;', '"')
            
            logger.info(f"HTML 내용 추출 (길이: {len(text)})")
            return text
        except Exception as e:
            logger.error(f"HTML 파싱 오류: {e}")
            return ""
    
    def analyze_email(self, email_path):
        """이메일 분석 메인 함수 (IT 서비스 예외 처리 추가)"""
        try:
            # 1. 이메일 파싱
            parsed_data = self.parse_email(email_path)
            if not parsed_data:
                return {
                    'verdict': 'error',
                    'risk_score': 100,
                    'risk_threshold': 70,
                    'body': {'total_matches': 0, 'categories': {}},
                    'header': {'final_verdict': 'error'},
                    'session_path': self.session_id,
                    'error': '이메일 파싱 실패'
                }
            
            # 현재 이메일 제목 저장 (텍스트 추출에 사용)
            self.current_email_subject = parsed_data.get('subject', '')
            
            # 2. 헤더 분석
            header_result = self.header_analyzer.analyze_email(parsed_data['raw_email'])
            
            # 3. 헤더 직접 검사
            msg = parsed_data['msg']
            
            # 헤더 인증 값 확인 - 직접 값을 확인
            spf_header = msg.get('Received-SPF', '')
            dkim_header = msg.get('DKIM-Signature', '')
            dmarc_header = msg.get('DMARC-Result', '')
            
            # 구글 서비스 이메일 특화 헤더 확인
            is_google_service = False
            from_header = parsed_data['msg'].get('From', '')
            google_dkim = msg.get('X-Google-DKIM-Signature', '')
            
            # 구글 서비스 이메일 확인
            if ('google.com' in from_header.lower() and google_dkim) or \
               ('noreply@google.com' in from_header.lower()) or \
               ('forms-receipts-noreply@google.com' in from_header.lower()):
                is_google_service = True
                logger.info("Google 서비스 이메일로 감지됨")
            
            # 1. SPF 확인
            if spf_header and 'pass' in spf_header.lower():
                header_result['spf_check'] = 'pass'
                logger.info(f"SPF 헤더 직접 확인 결과: pass")
            else:
                header_result['spf_check'] = 'unknown'
                if is_google_service:
                    header_result['spf_check'] = 'pass'
                    logger.info(f"구글 서비스 이메일: SPF 검증 신뢰")

            # 2. DKIM 확인
            if dkim_header:
                header_result['dkim_check'] = 'pass'
                logger.info(f"DKIM 서명 발견: pass")
            else:
                header_result['dkim_check'] = 'unknown'
                if is_google_service and google_dkim:
                    header_result['dkim_check'] = 'pass'
                    logger.info(f"구글 서비스 이메일: X-Google-DKIM-Signature로 DKIM 검증 신뢰")

            # 3. DMARC 확인
            if dmarc_header and 'pass' in dmarc_header.lower():
                header_result['dmarc_check'] = 'pass'
                logger.info(f"DMARC 결과 직접 확인: pass")
            else:
                header_result['dmarc_check'] = 'unknown'
                if is_google_service:
                    header_result['dmarc_check'] = 'none'
                    logger.info(f"구글 서비스 이메일: DMARC 없음 허용")
            
            # 3.2 발신자 도메인 추출 및 기관 유형 설정
            from_header = parsed_data['msg'].get('From', '')
            
            # 3.3 의심스러운 도메인 검사
            suspicious_domain = False
            suspicious_tlds = ['.pp.ua', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz']

            from_domain = self.header_analyzer.extract_domain_from_email(from_header)
            if from_domain:
                # 1단계: 항상 의심스러운 TLD 먼저 확인
                if any(from_domain.endswith(tld) for tld in suspicious_tlds):
                    suspicious_domain = True
                    header_result['domain_reputation'] = 'suspicious'
                    logger.warning(f"의심스러운 TLD 발견: {from_domain}")
                
                # 2단계: 다른 의심스러운 패턴 확인
                else:
                    if len(from_domain) > 30:
                        suspicious_domain = True
                        header_result['domain_reputation'] = 'suspicious'
                        logger.warning(f"비정상적으로 긴 도메인: {from_domain}")
                    
                    elif re.search(r'[bcdfghjklmnpqrstvwxz]{4,}', from_domain) or re.search(r'[a-z][0-9][a-z][0-9]', from_domain):
                        suspicious_domain = True
                        header_result['domain_reputation'] = 'suspicious'
                        logger.warning(f"랜덤 문자열 패턴 발견: {from_domain}")
                
                # 3단계: 도메인이 의심스럽지 않고 오래된 경우 신뢰할 수 있음으로 설정
                if not suspicious_domain:
                    domain_age_days = None
                    if 'details' in header_result and 'domain_info' in header_result['details']:
                        domain_info = header_result['details']['domain_info']
                        domain_age_days = domain_info.get('domain_age_days')
                        
                        if domain_age_days and domain_age_days >= 365:
                            header_result['domain_reputation'] = 'established'
                            logger.info(f"신뢰할 수 있는 도메인 (나이: {domain_age_days}일): {from_domain}")
            
            # 도메인에서 기관 유형 추출
            org_info = self.header_analyzer.get_organization_from_domain(from_header)
            header_result['organization_type'] = org_info["type"]
            header_result['organization_subtype'] = org_info["subtype"]
            
            # 4. 본문 분석
            html_body = parsed_data['body']
            text_body = self.extract_text_from_html(html_body)
            
            logger.info(f"총 추출된 내용 길이: {len(text_body)} 자, 내용: '{text_body[:500]}{'...' if len(text_body) > 500 else ''}'")
            
            # 텍스트가 추출되지 않은 경우, 제목에서 텍스트 추출 시도
            subject = parsed_data.get('subject', '')
            if not text_body and subject:
                logger.warning(f"본문에서 텍스트 추출 실패, 제목에서 텍스트 추출 시도: {subject}")
                text_body = subject
            
            # 기관 유형 정보 추출
            org_type = header_result.get('organization_type', 'unknown')
            org_subtype = header_result.get('organization_subtype', 'unknown')
            
            # 기관 유형 기반으로 본문 분석 (URL 분석 포함)
            body_result = self.body_analyzer.analyze_text(text_body, org_type, org_subtype)
            
            # URL 분석 결과 추출
            url_analysis = body_result.get('url_analysis', {})
            
            # 5. 첨부 파일 위험도 평가
            attachments = parsed_data['attachments']
            
            # 6. 최종 위험도 계산 (EmailHeaderAnalyzer의 org_types 활용)
            risk_score = 0
            risk_threshold = 70
            suspicious_threshold = 25  # suspicious 기준을 25로 낮춤
            reasons = []
            
            # EmailHeaderAnalyzer의 기관 도메인 정보 활용
            trusted_domains = self.header_analyzer.org_types
            domain_org_mapping = self.header_analyzer.domain_org_mapping
            
            # 공식 기관 도메인 여부 확인
            from_domain = header_result.get('sender_domain', '') or header_result.get('from_domain', '')
            is_official_domain = False
            is_government_domain = False
            is_trusted_company = False
            trusted_company_type = None
            trusted_company_subtype = None
            
            if from_domain:
                from_domain_lower = from_domain.lower()
                
                # 1. 한국 공식 기관 도메인들
                official_domains = ['.go.kr', '.or.kr', '.ac.kr', '.re.kr', '.pe.kr']
                government_domains = ['korea.kr', 'korea.go.kr', 'gov.kr']
                
                # 공식 기관 도메인 검사
                if any(from_domain_lower.endswith(domain) for domain in official_domains):
                    is_official_domain = True
                    if from_domain_lower.endswith('.go.kr'):
                        is_government_domain = True
                    logger.info(f"공식 기관 도메인 확인: {from_domain}")
                
                # 정부 공식 도메인 검사  
                elif any(from_domain_lower == domain or from_domain_lower.endswith('.' + domain) for domain in government_domains):
                    is_official_domain = True
                    is_government_domain = True
                    logger.info(f"정부 공식 도메인 확인: {from_domain}")
                
                # 2. EmailHeaderAnalyzer의 org_types에서 신뢰할 수 있는 기업 도메인 검사
                else:
                    # domain_org_mapping에서 직접 확인 (user 카테고리 제외)
                    if from_domain_lower in domain_org_mapping:
                        org_info = domain_org_mapping[from_domain_lower]
                        # user 카테고리는 신뢰할 수 있는 기업이 아님
                        if org_info["type"] != "user":
                            is_trusted_company = True
                            trusted_company_type = org_info["type"]
                            trusted_company_subtype = org_info["subtype"]
                            logger.info(f"신뢰할 수 있는 기업 도메인 확인: {from_domain} ({trusted_company_type}/{trusted_company_subtype})")
                        else:
                            logger.info(f"개인 이메일 도메인으로 분류: {from_domain} ({org_info['type']}/{org_info['subtype']})")
                    else:
                        # 서브도메인 확인 (user 카테고리 제외)
                        for trusted_domain, org_info in domain_org_mapping.items():
                            if from_domain_lower.endswith('.' + trusted_domain):
                                # user 카테고리는 신뢰할 수 있는 기업이 아님
                                if org_info["type"] != "user":
                                    is_trusted_company = True
                                    trusted_company_type = org_info["type"]
                                    trusted_company_subtype = org_info["subtype"]
                                    logger.info(f"신뢰할 수 있는 기업 서브도메인 확인: {from_domain} → {trusted_domain}")
                                    break
                                else:
                                    logger.info(f"개인 이메일 서브도메인으로 제외: {from_domain} → {trusted_domain}")
                    
                    # org_types에서 직접 검색 (더 포괄적)
                    if not is_trusted_company:
                        for subtype, domains in trusted_domains.items():
                            if subtype == "user":  # user 카테고리는 건너뛰기
                                continue
                                
                            for trusted_domain in domains:
                                if (from_domain_lower == trusted_domain or 
                                    from_domain_lower.endswith('.' + trusted_domain)):
                                    is_trusted_company = True
                                    
                                    # 서브타입을 기반으로 메인 타입 결정
                                    if subtype in ["government", "military", "public_corporation", "local_government"]:
                                        trusted_company_type = "public"
                                    elif subtype in ["bank", "insurance", "securities", "card"]:
                                        trusted_company_type = "financial"
                                    elif subtype in ["university", "school", "research"]:
                                        trusted_company_type = "education"
                                    elif subtype in ["it_software"]:
                                        trusted_company_type = "technology"
                                    else:
                                        trusted_company_type = "commercial"
                                    
                                    trusted_company_subtype = subtype
                                    logger.info(f"org_types에서 신뢰할 수 있는 기업 확인: {from_domain} → {trusted_domain}")
                                    break
                            if is_trusted_company:
                                break
                
                # 3. 기타 신뢰할 수 있는 한국 도메인 (.kr, .co.kr 등)
                if not is_official_domain and not is_trusted_company:
                    if from_domain_lower.endswith('.kr') or from_domain_lower.endswith('.co.kr'):
                        domain_age_days = None
                        if 'details' in header_result and 'domain_info' in header_result['details']:
                            domain_info = header_result['details']['domain_info']
                            domain_age_days = domain_info.get('domain_age_days')
                        
                        # 1년 이상된 .kr 도메인이고 SPF가 통과한 경우
                        if (domain_age_days and domain_age_days >= 365 and 
                            header_result.get('spf_check') in ['pass', 'match']):
                            is_official_domain = True
                            logger.info(f"신뢰할 수 있는 한국 도메인 확인: {from_domain} (나이: {domain_age_days}일)")
            
            # 조직 정보 추출
            org_type = header_result.get('organization_type', 'unknown')
            org_subtype = header_result.get('organization_subtype', 'unknown')
            
            # 공식 기관이나 신뢰할 수 있는 기업에서 발송되고 인증이 통과한 경우의 처리
            official_authenticated = (
                (is_official_domain or is_trusted_company) and 
                header_result.get('spf_check') in ['pass', 'match'] and
                header_result.get('dkim_check') in ['pass', 'none']
            )
            
            # IT 서비스 회사인지 확인
            is_it_service = (
                trusted_company_subtype == 'it_software' or
                (is_trusted_company and trusted_company_type == 'technology') or
                org_subtype == 'it_software'
            )

            logger.info(f"[DEBUG] IT 서비스 확인: trusted_company_subtype={trusted_company_subtype}, is_trusted_company={is_trusted_company}, trusted_company_type={trusted_company_type}, org_subtype={org_subtype}, is_it_service={is_it_service}")            
            # 7. 고위험 콘텐츠 패턴 검사 (IT 서비스 예외 처리 추가)
            high_risk_patterns = [
                r'긴급|즉시|당장|지금.*해야|빨리.*해야',  # 긴급성 강조
                r'비밀번호.*변경|패스워드.*재설정|로그인.*문제|계정.*문제',  # 계정 관련
                r'카드.*정지|계좌.*동결|한도.*초과|결제.*실패',  # 금융 위협
                r'개인정보.*확인|신분.*인증|본인.*확인|실명.*인증',  # 개인정보 요구
                r'링크.*클릭|아래.*확인|여기.*접속|바로.*이동',  # 행동 유도
                r'24시간|48시간|3일.*이내|오늘.*마감|내일.*마감',  # 시간 압박
                r'법적.*조치|고발|송금|처벌|소송|경찰서|검찰청',  # 법적 위협
                r'당첨|축하.*드립|무료.*제공|공짜|100%.*할인',  # 미끼성 내용
                r'사기.*의심|허위.*신고|명의.*도용|불법.*사용',  # 위협적 내용
                r'OTP|인증번호|보안카드|공인인증서|휴대폰.*인증'  # 보안 정보 요구
            ]
            
            # IT 서비스에서 정상적인 패턴들 (제외할 패턴)
            it_service_normal_patterns = [
                r'^로그인$',  # 단순 "로그인" 단어
                r'로그인.*알림',  # 로그인 알림
                r'새.*로그인',  # 새 로그인
                r'로그인.*시도',  # 로그인 시도
                r'로그인.*성공',  # 로그인 성공
                r'계정.*생성',  # 계정 생성
                r'계정.*활성화',  # 계정 활성화
                r'비밀번호.*설정',  # 비밀번호 설정 (변경/재설정과 다름)
                r'인증.*완료',  # 인증 완료
                r'인증.*메일',  # 인증 메일
                r'보안.*알림',  # 보안 알림
                r'접속.*알림',  # 접속 알림
                r'새.*기기.*로그인',  # 새 기기 로그인
            ]
            
            high_risk_content = False
            high_risk_count = 0
            high_risk_examples = []
            text_content = text_body + ' ' + subject  # 제목과 본문 통합 검사
            
            for pattern in high_risk_patterns:
                matches = re.findall(pattern, text_content, re.IGNORECASE)
                if matches:
                    # IT 서비스 회사의 경우 정상 패턴인지 확인
                    if is_it_service:
                        is_normal_pattern = False
                        for normal_pattern in it_service_normal_patterns:
                            if re.search(normal_pattern, text_content, re.IGNORECASE):
                                is_normal_pattern = True
                                logger.info(f"IT 서비스 정상 패턴으로 제외: {normal_pattern}")
                                break
                        
                        if is_normal_pattern:
                            logger.info(f"IT 서비스에서 정상 패턴 제외: {pattern}")
                            continue  # 정상 패턴이면 건너뛰기
                    
                    high_risk_count += len(matches)
                    high_risk_content = True
                    high_risk_examples.extend(matches[:2])
                    logger.warning(f"고위험 패턴 발견: {pattern} -> {matches}")
            
            if high_risk_content:
                logger.warning(f"고위험 콘텐츠 패턴 {high_risk_count}개 발견")
            elif is_it_service:
                logger.info(f"IT 서비스 회사에서 고위험 패턴 제외 처리 완료")
            
            # 8. 헤더 검사 결과 기반 위험도 계산
            if header_result.get('spf_check') not in ['pass', 'match', 'not_applicable']:
                risk_score += 15
                reasons.append(f"SPF 검증 실패: +15")

            # 신뢰할 수 있는 IT 서비스는 SPF만 통과하면 DKIM/DMARC 완전 면제
            if is_trusted_company and is_it_service and header_result.get('spf_check') in ['pass', 'match']:
                logger.info("신뢰할 수 있는 IT 서비스 + SPF 통과: DKIM/DMARC 검증 실패 점수 완전 면제")
                # DKIM/DMARC 점수 부여 안함
            elif not official_authenticated:
                # 나머지 경우에만 DKIM/DMARC 점수 부여
                if header_result.get('dkim_check') not in ['pass', 'none']:
                    if is_it_service:
                        risk_score += 8
                        reasons.append(f"DKIM 검증 실패 (IT 서비스): +8")
                    else:
                        risk_score += 15
                        reasons.append(f"DKIM 검증 실패: +15")
                
                if header_result.get('dmarc_check') not in ['pass', 'none']:
                    if is_it_service:
                        risk_score += 3
                        reasons.append(f"DMARC 검증 실패 (IT 서비스): +3")
                    else:
                        risk_score += 5
                        reasons.append(f"DMARC 검증 실패: +5")
            else:
                # 신뢰할 수 있는 기관이라도 고위험 콘텐츠가 있으면 인증 실패에 점수 부여
                if high_risk_content:
                    if header_result.get('dkim_check') not in ['pass', 'none']:
                        risk_score += 8  # 완화된 점수
                        reasons.append(f"DKIM 검증 실패 (고위험 콘텐츠): +8")
                    
                    if header_result.get('dmarc_check') not in ['pass', 'none']:
                        risk_score += 3  # 완화된 점수
                        reasons.append(f"DMARC 검증 실패 (고위험 콘텐츠): +3")
                    
                    logger.warning(f"신뢰할 수 있는 기관이지만 고위험 콘텐츠로 인한 인증 실패 점수 부여")
                else:
                    logger.info("신뢰할 수 있는 기관/기업 + 저위험 콘텐츠: DKIM/DMARC 실패 점수 면제")
            
            # 9. 고위험 콘텐츠 패턴 점수 (인증과 무관하게 부여, IT 서비스 예외)
            if high_risk_content:
                high_risk_score = min(high_risk_count * 8, 50)  # 패턴당 8점, 최대 50점
                
                # 신뢰할 수 있는 기관이라도 고위험 콘텐츠는 점수 부여 (완화만)
                if official_authenticated:
                    high_risk_score = max(high_risk_score * 0.6, 10)  # 40% 완화, 최소 10점
                    logger.warning(f"신뢰할 수 있는 기관에서 고위험 콘텐츠: 완화된 점수 부여")
                
                risk_score += high_risk_score
                reasons.append(f"고위험 콘텐츠 패턴 {high_risk_count}개: +{high_risk_score}")
            
            # 10. 도메인 평판 기반 위험도
            domain_age_days = None
            domain_reputation_adjusted = False
            
            if header_result.get('domain_reputation') == 'suspicious':
                is_suspicious_domain = suspicious_domain
                
                if 'details' in header_result and 'domain_info' in header_result['details']:
                    domain_info = header_result['details']['domain_info']
                    domain_age_days = domain_info.get('domain_age_days')
                    
                    if domain_age_days and domain_age_days >= 365 and not is_suspicious_domain:
                        domain_reputation_adjusted = True
                        header_result['domain_reputation_adjusted'] = True
                        logger.info(f"[조정] 도메인이 {domain_age_days}일 된 안정적인 도메인으로 판단")
                    else:
                        domain_reputation_score = 25
                        risk_score += domain_reputation_score
                        reasons.append(f"도메인 평판 의심: +{domain_reputation_score}")
                else:
                    domain_reputation_score = 25
                    risk_score += domain_reputation_score
                    reasons.append(f"도메인 평판 의심: +{domain_reputation_score}")
            
            # 11. 사칭 의심 기반 위험도 (개인 이메일 도메인 예외 처리 추가)
            # 카테고리별 키워드 패턴 분류
            subject_suspicious_patterns = {

                # financial 카테고리 키워드

                'financial': [

                    r'은행|카드|신한|우리|국민|농협|하나|bank|card'

                ],

                # government 카테고리 키워드

                'government': [

                    r'정부|공공|공단|국세|세무|우체국|우편|코리아|한국|서울시'

                ],

                # delivery 카테고리 키워드

                'delivery': [

                    r'택배|배송|우체국|우편|한진|post|delivery'

                ],

                # malicious 카테고리 키워드

                'malicious': [

                    r'로그인'

                ],

                # 기본 의심 패턴

                'general': [

                    r'(주문|결제).*확인',

                    r'(지금|즉시).*확인',

                    r'링크.*클릭',

                    r'비밀번호|인증|코드'

                ]

            }

            impersonation_found = False

            # 개인 이메일 도메인인지 확인
            is_personal_email = self.header_analyzer.is_user_email_domain(from_domain)

            # 구글 서비스, 개인 이메일은 사칭 검사 제외/완화
            if not is_google_service and not is_personal_email:
                for category, patterns in subject_suspicious_patterns.items():
                    category_match_found = False
                    
                    for pattern in patterns:
                        if re.search(pattern, subject.lower(), re.IGNORECASE) or re.search(pattern, from_header.lower(), re.IGNORECASE):
                            # 카테고리별 예외 처리
                            should_skip = False
                            
                            # IT 서비스 회사에서 IT 관련 키워드는 정상
                            if category == 'it' and is_it_service:
                                logger.info(f"IT 서비스 회사에서 {category} 카테고리 키워드 제외: {pattern}")
                                should_skip = True
                            
                            # 금융기관에서 금융 관련 키워드는 정상 (일부 완화)
                            elif category == 'financial' and trusted_company_type == 'financial':
                                logger.info(f"금융기관에서 {category} 카테고리 키워드 제외: {pattern}")
                                should_skip = True
                            
                            # 정부기관에서 정부 관련 키워드는 정상
                            elif category == 'government' and is_government_domain:
                                logger.info(f"정부기관에서 {category} 카테고리 키워드 제외: {pattern}")
                                should_skip = True
                            
                            # 배송업체에서 배송 관련 키워드는 정상
                            elif category == 'delivery' and trusted_company_subtype in ['delivery', 'logistics']:
                                logger.info(f"배송업체에서 {category} 카테고리 키워드 제외: {pattern}")
                                should_skip = True
                            
                            if not should_skip:
                                if from_domain and not any(official in from_domain for official in ['.kr', 'korea', 'post.go', 'epost']):
                                    category_match_found = True
                                    logger.warning(f"사칭 의심 ({category}): 키워드 패턴이 있지만 공식 도메인이 아님")
                                    break
                    
                    if category_match_found:
                        impersonation_found = True
                        break

            elif is_personal_email:
                logger.info("개인 이메일 도메인: 사칭 검사 제외")

            if impersonation_found:
                impersonation_score = 35
                risk_score += impersonation_score
                reasons.append(f"공식 기관/회사 사칭 의심: +{impersonation_score}")
            # 12. 사용자 계정에서 기관 사칭
            if header_result.get('organization_type') == 'user':
                gov_count = body_result.get('categories', {}).get('government', {}).get('count', 0)
                inv_count = body_result.get('categories', {}).get('investigation', {}).get('count', 0)
                
                if gov_count > 0 or inv_count > 0:
                    impersonation_score = 40
                    risk_score += impersonation_score
                    reasons.append(f"사용자 계정의 정부기관/수사기관 사칭 의심: +{impersonation_score}")
                    logger.warning("사용자 계정에서 정부기관/수사기관 사칭 의심 발견")
            
            # 13. URL 위험도 계산 (강화된 검사)
            if url_analysis['risk_score'] > 0:
                # 신뢰할 수 있는 기관/기업에서 발송된 경우에도 의심스러운 URL은 엄격히 검사
                if official_authenticated:
                    adjusted_suspicious_urls = []
                    for url_info in url_analysis['suspicious_urls']:
                        url = url_info['url']
                        url_features = url_info['features'][:]
                        
                        # URL에서 도메인 추출
                        url_domain_match = re.search(r'https?://([^/]+)', url)
                        if url_domain_match:
                            url_domain = url_domain_match.group(1).lower()
                            
                            # 발신자 도메인과 URL 도메인 관계 확인
                            is_same_or_related = (
                                from_domain.lower() in url_domain or 
                                url_domain in from_domain.lower() or
                                url_domain.endswith('.kr')
                            )
                            
                            # 같은/관련 도메인이라도 위험한 패턴은 유지
                            dangerous_features = ['has_ip', 'suspicious_tld', 'suspicious_params', 'url_shortener']
                            has_dangerous_features = any(feature in url_features for feature in dangerous_features)
                            
                            if is_same_or_related and not has_dangerous_features and not high_risk_content:
                                # 브랜드 사칭만 제거, 고위험 콘텐츠가 있으면 완화 제한
                                if 'brand_impersonation' in url_features:
                                    url_features.remove('brand_impersonation')
                                    logger.info(f"신뢰할 수 있는 관련 도메인: 브랜드 사칭 제거 - {url}")
                            elif has_dangerous_features or high_risk_content:
                                logger.warning(f"신뢰할 수 있는 기관이지만 위험한 URL 패턴 발견: {url}")
                        
                        # 특징이 남아있는 경우 의심스러운 URL로 유지
                        if url_features:
                            # 위험도 재계산
                            url_info['features'] = url_features
                            weights = {
                                'has_ip': 25, 'suspicious_tld': 15, 'long_subdomain': 10,
                                'url_shortener': 8, 'suspicious_keywords': 20, 'excessive_hyphens': 5,
                                'numeric_domain': 8, 'brand_impersonation': 25, 'long_url': 5,
                                'suspicious_params': 15, 'confusing_chars': 10, 'hangul_domain': 8,
                                'suspicious_port': 12
                            }
                            new_risk_score = sum(weights.get(feature, 0) for feature in url_features)
                            url_info['risk_score'] = min(new_risk_score, 100)
                            
                            if url_info['risk_score'] > 0:
                                adjusted_suspicious_urls.append(url_info)
                    
                    # 조정된 URL 목록으로 업데이트
                    url_analysis['suspicious_urls'] = adjusted_suspicious_urls
                    
                    # 조정된 위험도 재계산
                    if adjusted_suspicious_urls:
                        url_analysis['risk_score'] = max(url['risk_score'] for url in adjusted_suspicious_urls)
                    else:
                        url_analysis['risk_score'] = 0
                    
                    logger.info(f"신뢰할 수 있는 기관/기업 URL 분석 조정 완료: 의심스러운 URL {len(adjusted_suspicious_urls)}개")
                
                # URL 위험도 적용 (고위험 콘텐츠가 있으면 완화 제한)
                if url_analysis['risk_score'] > 0:
                    if official_authenticated and not high_risk_content:
                        url_risk_score = min(url_analysis['risk_score'] * 0.6, 25)  # 40% 완화, 최대 25점
                    else:
                        url_risk_score = min(url_analysis['risk_score'], 40)  # 최대 40점
                    
                    risk_score += url_risk_score
                    reasons.append(f"의심스러운 URL 발견 ({len(url_analysis['suspicious_urls'])}개): +{url_risk_score}")
                    
                    # 특정 URL 특징에 대한 추가 위험도
                    features_detected = url_analysis.get('features_detected', [])
                    
                    if 'has_ip' in features_detected:
                        ip_score = 8 if (official_authenticated and not high_risk_content) else 15
                        risk_score += ip_score
                        reasons.append(f"IP 주소 직접 사용 URL: +{ip_score}")
                    
                    if 'brand_impersonation' in features_detected:
                        brand_score = 10 if (official_authenticated and not high_risk_content) else 20
                        risk_score += brand_score
                        reasons.append(f"브랜드 사칭 URL: +{brand_score}")
                    
                    if 'suspicious_tld' in features_detected:
                        tld_score = 6 if (official_authenticated and not high_risk_content) else 10
                        risk_score += tld_score
                        reasons.append(f"의심스러운 TLD URL: +{tld_score}")
                    
                    if 'suspicious_params' in features_detected:
                        param_score = 10 if (official_authenticated and not high_risk_content) else 15
                        risk_score += param_score
                        reasons.append(f"의심스러운 URL 파라미터: +{param_score}")
                    
                    if 'url_shortener' in features_detected:
                        short_score = 5 if (official_authenticated and not high_risk_content) else 8
                        risk_score += short_score
                        reasons.append(f"URL 단축 서비스 사용: +{short_score}")
            
            # 14. 본문 키워드 매치 기반 위험도 (IT 서비스 강화된 예외 처리)
            if body_result['total_matches'] > 0:
                weights = {
                    'malicious': 15,
                    'financial': 10,
                    'investigation': 10,
                    'government': 8,
                    'military': 12,
                    'education': 5,
                    'delivery': 15
                }
                
                for category, info in body_result['categories'].items():
                    category_weight = weights.get(category, 5)
                    
                    # 신뢰할 수 있는 기관/기업에서 해당 기관 관련 키워드 처리
                    if official_authenticated and not high_risk_content:
                        # 정부 기관에서 government 키워드는 정상 (고위험 콘텐츠 없을 때만)
                        if is_government_domain and category == 'government':
                            logger.info(f"정부 기관에서 {category} 키워드: 점수 부여 안함")
                            continue
                        
                        # IT 서비스에서 malicious 키워드는 대폭 완화 (로그인, 계정, 비밀번호 등)
                        elif is_it_service and category == 'malicious':
                            if info['count'] <= 10:  # IT 서비스는 더 관대하게
                                category_weight = max(1, category_weight // 5)  # 대폭 완화
                                logger.info(f"IT 서비스에서 {category} 키워드: 대폭 완화 ({category_weight})")
                            
                            if info['count'] <= 5:  # 5개 이하면 완전 제외
                                logger.info(f"IT 서비스에서 {category} 키워드 {info['count']}개: 완전 제외")
                                continue
                        
                        # 신뢰할 수 있는 기업에서 해당 카테고리 키워드는 완화
                        elif trusted_company_subtype:
                            if trusted_company_subtype in ['bank', 'insurance', 'securities', 'card'] and category == 'financial':
                                if info['count'] <= 5:  # 5개 이하면 완화
                                    category_weight = max(1, category_weight // 2)
                                    logger.info(f"{trusted_company_subtype} 기관에서 {category} 키워드: 가중치 완화")
                                else:
                                    logger.warning(f"{trusted_company_subtype} 기관이지만 {category} 키워드가 많음: 정상 점수")
                                
                                if info['count'] <= 3:  # 3개 이하면 완전 제외
                                    logger.info(f"{trusted_company_subtype} 기관에서 {category} 키워드 {info['count']}개: 완전 제외")
                                    continue
                            
                            elif trusted_company_subtype in ['university', 'school', 'research'] and category == 'education':
                                if info['count'] <= 5:
                                    category_weight = max(1, category_weight // 2)
                                    logger.info(f"{trusted_company_subtype} 기관에서 {category} 키워드: 가중치 완화")
                                
                                if info['count'] <= 3:  # 3개 이하면 완전 제외
                                    logger.info(f"{trusted_company_subtype} 기관에서 {category} 키워드 {info['count']}개: 완전 제외")
                                    continue
                            
                            # 배송업체에서 delivery 키워드 완화
                            elif trusted_company_subtype in ['delivery', 'logistics'] and category == 'delivery':
                                if info['count'] <= 5:
                                    category_weight = max(1, category_weight // 2)
                                    logger.info(f"{trusted_company_subtype} 기관에서 {category} 키워드: 가중치 완화")
                                
                                if info['count'] <= 3:  # 3개 이하면 완전 제외
                                    logger.info(f"{trusted_company_subtype} 기관에서 {category} 키워드 {info['count']}개: 완전 제외")
                                    continue
                        
                        # 악성 키워드는 신뢰할 수 있는 기관/기업이라도 완화만 (완전 제외 안함)
                        if category == 'malicious' and info['count'] <= 3 and not is_it_service:
                            category_weight = max(2, category_weight // 3)  # 최소 2점 보장
                            logger.info(f"신뢰할 수 있는 기관/기업에서 적은 수의 {category} 키워드: 가중치 완화 ({category_weight})")
                    
                    # 고위험 콘텐츠가 있으면 키워드 완화 제한
                    elif official_authenticated and high_risk_content:
                        if category == 'malicious':
                            category_weight = max(category_weight // 2, 5)  # 절반 완화, 최소 5점
                            logger.warning(f"신뢰할 수 있는 기관이지만 고위험 콘텐츠로 인한 제한된 완화: {category}")
                    
                    category_score = min(category_weight * info['count'], 25)
                    risk_score += category_score
                    reasons.append(f"{category} 카테고리 키워드 {info['count']}개: +{category_score}")

            # 제외된 카테고리 로깅
            if 'excluded_categories' in body_result and body_result['excluded_categories']:
                logger.info("=== 제외된 카테고리 ===")
                for category, info in body_result['excluded_categories'].items():
                    logger.info(f"{category}: {info['count']}개 키워드 제외 - {info['reason']}")
            
            # 15. 제목에서 직접 키워드 검사 (카테고리별 예외 처리 강화)
            subject_matches = 0
            excluded_patterns = []

            for category, patterns in subject_suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, subject, re.IGNORECASE):
                        # 카테고리별 예외 처리
                        should_exclude = False
                        
                        # IT 서비스에서 IT 관련 키워드는 정상
                        if category == 'it' and is_it_service:
                            should_exclude = True
                            excluded_patterns.append(f"{pattern} (IT 서비스)")
                        
                        # 금융기관에서 금융 관련 키워드는 정상
                        elif category == 'financial' and trusted_company_type == 'financial':
                            should_exclude = True
                            excluded_patterns.append(f"{pattern} (금융기관)")
                        
                        # 정부기관에서 정부 관련 키워드는 정상
                        elif category == 'government' and is_government_domain:
                            should_exclude = True
                            excluded_patterns.append(f"{pattern} (정부기관)")
                        
                        # 배송업체에서 배송 관련 키워드는 정상
                        elif category == 'delivery' and trusted_company_subtype in ['delivery', 'logistics']:
                            should_exclude = True
                            excluded_patterns.append(f"{pattern} (배송업체)")
                        
                        if not should_exclude:
                            subject_matches += 1

            if excluded_patterns:
                logger.info(f"제목 키워드 검사에서 제외된 패턴: {excluded_patterns}")

            if subject_matches > 0:
                if official_authenticated and not high_risk_content:
                    subject_score = min(subject_matches * 3, 15)  # 완화된 점수
                else:
                    subject_score = min(subject_matches * 5, 20)  # 정상 점수
                
                risk_score += subject_score
                reasons.append(f"제목에 의심스러운 키워드 {subject_matches}개: +{subject_score}")            
            # 16. 구글 서비스 이메일의 경우 위험도 점수 조정
            if is_google_service:
                original_risk_score = risk_score
                
                if "사칭" in ' '.join(reasons) or "도메인 평판" in ' '.join(reasons):
                    # 고위험 콘텐츠가 있으면 조정 제한
                    if high_risk_content:
                        adjusted_risk_score = max(risk_score - 20, 10)  # 제한된 조정
                    else:
                        adjusted_risk_score = max(risk_score - 35, 0)  # 기존 조정
                    
                    risk_score = adjusted_risk_score
                    reasons.append(f"Google 서비스 이메일 인식: 위험도 조정 {original_risk_score} → {adjusted_risk_score}")
                    logger.info(f"Google 서비스 이메일 인식으로 위험도 조정")
            
            # 17. 신뢰할 수 있는 기관/기업 인증 메일에 대한 최종 조정 (개인 이메일 제외)
            if official_authenticated and risk_score > 0 and not is_personal_email:
                original_score = risk_score
                
                # 고위험 콘텐츠가 있으면 조정 제한
                if high_risk_content:
                    # 정부 기관
                    if is_government_domain:
                        risk_score = max(0, risk_score - 15)  # 제한된 조정
                        reasons.append(f"정부 공식 도메인 + 인증 통과 (고위험 콘텐츠): 위험도 -15 ({original_score} → {risk_score})")
                    # 금융기관
                    elif trusted_company_type == 'financial':
                        risk_score = max(0, risk_score - 12)  # 제한된 조정
                        reasons.append(f"금융기관 도메인 + 인증 통과 (고위험 콘텐츠): 위험도 -12 ({original_score} → {risk_score})")
                    # IT 서비스
                    elif is_it_service:
                        risk_score = max(0, risk_score - 20)  # IT 서비스는 더 큰 조정
                        reasons.append(f"IT 서비스 도메인 + 인증 통과 (고위험 콘텐츠): 위험도 -20 ({original_score} → {risk_score})")
                    # 기타 신뢰할 수 있는 기관/기업
                    else:
                        risk_score = max(0, risk_score - 10)  # 제한된 조정
                        reasons.append(f"신뢰할 수 있는 기관/기업 도메인 + 인증 통과 (고위험 콘텐츠): 위험도 -10 ({original_score} → {risk_score})")
                else:
                    # 정부 기관
                    if is_government_domain:
                        risk_score = max(0, risk_score - 30)
                        reasons.append(f"정부 공식 도메인 + 인증 통과: 위험도 -30 ({original_score} → {risk_score})")
                    # 금융기관
                    elif trusted_company_type == 'financial':
                        risk_score = max(0, risk_score - 25)
                        reasons.append(f"금융기관 도메인 + 인증 통과: 위험도 -25 ({original_score} → {risk_score})")
                    # IT 서비스
                    elif is_it_service:
                        risk_score = max(0, risk_score - 35)  # IT 서비스는 가장 큰 조정
                        reasons.append(f"IT 서비스 도메인 + 인증 통과: 위험도 -35 ({original_score} → {risk_score})")
                    # 기타 신뢰할 수 있는 기관/기업
                    else:
                        risk_score = max(0, risk_score - 20) 
                        reasons.append(f"신뢰할 수 있는 기관/기업 도메인 + 인증 통과: 위험도 -20 ({original_score} → {risk_score})")
                
                logger.info(f"신뢰할 수 있는 기관/기업 최종 조정: {original_score} → {risk_score}")
            
            # 18. 최종 위험도 점수 제한
            risk_score = min(risk_score, 100)
            
            # 로그에 각 위험 요소 기록 (중복 제거)
            unique_reasons = []
            for reason in reasons:
                if reason not in unique_reasons:
                    unique_reasons.append(reason)
                    logger.info(f"위험 요소: {reason}")
            
            # 헤더 분석에서 발견된 위험 이유 추가
            header_result['reasons'] = unique_reasons
            
            # 19. 최종 판정
            verdict = 'legitimate'
            if risk_score >= risk_threshold:
                verdict = 'dangerous'
            elif risk_score >= suspicious_threshold:
                verdict = 'suspicious'
            
            # 고위험 콘텐츠가 있으면 최소 suspicious (IT 서비스 예외)
            if high_risk_content and verdict == 'legitimate' and not is_it_service:
                verdict = 'suspicious'
                logger.warning("고위험 콘텐츠로 인한 판정 상향: legitimate → suspicious")
            
            # 신뢰할 수 있는 기관/기업 인증 메일이고 위험도가 낮은 경우 legitimate으로 조정
            if official_authenticated and not high_risk_content:
                # IT 서비스는 더 관대한 기준
                threshold = 35 if is_it_service else 25
                if risk_score < threshold:
                    if verdict != 'legitimate':
                        logger.info(f"신뢰할 수 있는 기관/기업 인증 메일 (저위험): {verdict} → legitimate")
                        verdict = 'legitimate'
            
            # 구글 서비스 이메일이고 위험도가 낮은 경우 legitimate으로 조정
            if is_google_service and not high_risk_content and risk_score < 30:
                if verdict != 'legitimate':
                    logger.info(f"Google 서비스 이메일 (저위험): {verdict} → legitimate")
                    verdict = 'legitimate'
            
            logger.info(f"최종 위험도 점수: {risk_score}/{risk_threshold}, 판정: {verdict}")
            logger.info(f"고위험 콘텐츠: {high_risk_content}, IT 서비스: {is_it_service}, 도메인 평판 조정: {domain_reputation_adjusted}")
            
            # 메타데이터 정보 추가
            metadata = {}
            for name, value in msg.items():
                metadata[name] = str(value)
            
            # 결과 종합
            result = {
                'verdict': verdict,
                'risk_score': risk_score,
                'risk_threshold': risk_threshold,
                'body': body_result,
                'header': header_result,
                'attachments': attachments,
                'session_path': self.session_id,
                'reasons': unique_reasons,
                'subject': parsed_data.get('subject', ''),
                'metadata': metadata,
                'domain_reputation_adjusted': domain_reputation_adjusted,
                'is_google_service': is_google_service,
                'url_analysis': url_analysis,
                'high_risk_content': high_risk_content,
                'high_risk_patterns': high_risk_examples if high_risk_content else [],
                'is_it_service': is_it_service
            }
            
            # 도메인 평판 정보 추가
            if domain_age_days:
                result['domain_age_days'] = domain_age_days
            
            # 결과 JSON 파일로 저장
            result_path = self.result_dir / "analysis_result.json"
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            # AI 분석 수행 (기본 분석 후)
            if AI_ENABLED and ANTHROPIC_AVAILABLE and ANTHROPIC_API_KEY:
               email_data = {
                   'subject': parsed_data.get('subject', ''),
                   'from': parsed_data['msg'].get('From', ''),
                   'body': text_body
               }
               
               ai_result = self.analyze_with_claude(email_data, result)
               if ai_result:
                   # AI 분석 결과 추가
                   result['ai_analysis'] = ai_result
                   
                   # 최종 위험도 조정 (가중 평균)
                   ai_risk_score = ai_result.get('risk_score', 0)
                   if ai_risk_score > 0:
                       original_score = result['risk_score']
                       # 가중 평균 계산 (기본 분석 60%, AI 분석 40%)
                       adjusted_score = (original_score * 0.6) + (ai_risk_score * 0.4)
                       result['risk_score'] = round(adjusted_score)
                       result['ai_adjusted'] = True
                       logger.info(f"위험도 점수 조정: {original_score} → {result['risk_score']} (AI 평가: {ai_risk_score})")
           
            return result
           
        except Exception as e:
            logger.error(f"이메일 분석 중 오류 발생: {e}")
            import traceback
            logger.error(traceback.format_exc())
           
            return {
                'verdict': 'error',
                'risk_score': 0,
                'risk_threshold': 70,
                'body': {'total_matches': 0, 'categories': {}},
                'header': {'final_verdict': 'error'},
                'session_path': self.session_id,
                'error': str(e)
            }