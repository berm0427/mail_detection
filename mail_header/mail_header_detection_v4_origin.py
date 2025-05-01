import email
import re
import whois
import dns.resolver
import ipaddress
import logging
import os
import sys
import socket
import traceback
from io import BytesIO
from email import policy
from email.parser import BytesParser

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EmailHeaderAnalyzer:
    def __init__(self):
        self.spf_ip_list = []
        self.dig_ip_list = []
        self.domains_analyzed = set()  # 이미 분석한 도메인 추적
        
        # 결과 초기화
        self.reset_analysis_result()
        
        # 기관 분류 데이터베이스 - 세분화 및 추가
        self.org_types = {
            # 공공기관
            "government": [
                "go.kr",        # 한국 정부기관
                "gov",          # 미국 정부
                "gov.cn",       # 중국 정부
                "gc.ca",        # 캐나다 정부
                "gob.mx",       # 멕시코 정부
                "gov.uk",       # 영국 정부
                "admin.ch",     # 스위스 정부
                "korea.kr",     # 대한민국 정부
            ],
            "military": [
                "mil.kr",       # 한국 군
                "mil",          # 미국 군
                "dongwon.mil.kr", # 동원 (군사)
                "defense.gov",  # 미국 국방부
                "army.mil",     # 미국 육군
                "navy.mil",     # 미국 해군
                "af.mil",       # 미국 공군
            ],
            "public_corporation": [
                "korail.com",    # 철도공사
                "kepco.co.kr",   # 한국전력
                "kwater.or.kr",  # 수자원공사
                "kogas.or.kr",   # 가스공사
                "lh.or.kr",      # 토지주택공사
                "kotra.or.kr",   # 대한무역투자진흥공사
            ],
            "local_government": [
                "seoul.go.kr",    # 서울시
                "busan.go.kr",    # 부산시
                "incheon.go.kr",  # 인천시
                "daegu.go.kr",    # 대구시
                "daejeon.go.kr",  # 대전시
                "gwangju.go.kr",  # 광주시
                "ulsan.go.kr",    # 울산시
                "gyeonggi.go.kr", # 경기도
            ],
            
            # 금융기관
            "bank": [
                "shinhan.com",     # 신한은행
                "kbstar.com",      # KB국민은행
                "wooribank.com",   # 우리은행
                "ibk.co.kr",       # 기업은행
                "hanabank.com",    # 하나은행
                "keb.co.kr",       # 외환은행
                "nhbank.com",      # 농협은행
                "suhyup-bank.com", # 수협은행
                "citibank.co.kr",  # 시티은행
                "kdb.co.kr",       # 산업은행
                "epostbank.go.kr", # 우체국은행
                "hsbc.co.kr",      # HSBC
                "sc.com",          # SC은행
                "standardchartered.co.kr", # SC제일은행
            ],
            "insurance": [
                "samsungfire.com",   # 삼성화재
                "kbinsure.co.kr",    # KB손해보험
                "hanwhalife.com",    # 한화생명
                "kyobo.com",         # 교보생명
                "lina.co.kr",        # 라이나생명
                "meritzfire.com",    # 메리츠화재
                "klia.or.kr",        # 생명보험협회
                "igi.co.kr",         # 교보손해보험
                "koreanre.co.kr",    # 코리안리
            ],
            "securities": [
                "miraeasset.com",    # 미래에셋
                "kbsec.com",         # KB증권
                "samsungpop.com",    # 삼성증권
                "shinhaninvest.com", # 신한금융투자
                "hanwhawm.com",      # 한화투자증권
                "nhqv.com",          # NH투자증권
            ],
            "card": [
                "shinhancard.com",   # 신한카드
                "kbcard.com",        # KB국민카드
                "samsungcard.com",   # 삼성카드
                "hyundaicard.com",   # 현대카드
                "lottecard.co.kr",   # 롯데카드
                "bccard.com",        # BC카드
            ],
            
            # 교육기관
            "university": [
                "snu.ac.kr",        # 서울대
                "yonsei.ac.kr",     # 연세대
                "kaist.ac.kr",      # KAIST
                "korea.ac.kr",      # 고려대
                "skku.edu",         # 성균관대
                "sch.ac.kr",        # 순천향대
                "harvard.edu",      # 하버드
                "stanford.edu",     # 스탠포드
                "mit.edu",          # MIT
                "ac.kr",            # 한국 대학 일반
                "edu",              # 미국 교육기관
            ],
            "school": [
                "hs.kr",            # 고등학교
                "ms.kr",            # 중학교
                "es.kr",            # 초등학교
                "k12.il.us",        # 미국 K-12
                "school.uk",        # 영국 학교
            ],
            "research": [
                "kist.re.kr",       # 과학기술연구원
                "etri.re.kr",       # 전자통신연구원
                "kari.re.kr",       # 항공우주연구원
                "re.kr",            # 한국 연구기관
            ],
            
            # IT/소프트웨어
            "it_software": [
                "naver.com",        # 네이버
                "navercorp.com",    # 네이버 계열사(ex: 네이버페이 등)    
                "kakao.com",        # 카카오
                "line.me",          # 라인
                "coupang.com",      # 쿠팡
                "nexon.com",        # 넥슨
                "ncsoft.com",       # 엔씨소프트
                "krafton.com",      # 크래프톤
                "microsoft.com",    # 마이크로소프트
                "google.com",       # 구글
                "apple.com",        # 애플
                "amazon.com",       # 아마존
                "facebook.com",     # 페이스북
                "oracle.com",       # 오라클
                "ibm.com",          # IBM
                "intel.com",        # 인텔
                "rm.ahnlab.com",    # 안랩
                "everytime.kr",     # 에브리타임
            ],
            "telecom": [
                "sktelecom.com",    # SK텔레콤
                "kt.com",           # KT
                "uplus.co.kr",      # LG유플러스
                "lguplus.co.kr",    # LG유플러스
                "att.com",          # AT&T
                "verizon.com",      # Verizon
                "tmobile.com",      # T-Mobile
                "vodafone.com",     # Vodafone
                "orange.com",       # Orange
                "ntt.com",          # NTT
            ],
            "manufacturing": [
                "samsung.com",      # 삼성
                "hyundai.com",      # 현대
                "kia.com",          # 기아
                "lg.com",           # LG
                "posco.com",        # 포스코
                "hanwha.com",       # 한화
                "doosan.com",       # 두산
                "sk.com",           # SK
                "gm.com",           # GM
                "toyota.com",       # 토요타
                "ford.com",         # 포드
                "siemens.com",      # 지멘스
                "ge.com",           # GE
            ],
            "electronics": [
                "samsung.com",      # 삼성전자
                "lg.com",           # LG전자
                "sonyelectronics.com", # 소니
                "panasonic.com",    # 파나소닉
                "philips.com",      # 필립스
                "bose.com",         # 보스
                "sony.com",         # 소니
            ],
            "retail_logistics": [
                "emart.com",        # 이마트
                "homeplus.co.kr",   # 홈플러스
                "lotte.com",        # 롯데
                "coupang.com",      # 쿠팡
                "gmarket.co.kr",    # G마켓
                "11st.co.kr",       # 11번가
                "amazon.com",       # 아마존
                "walmart.com",      # 월마트
                "costco.com",       # 코스트코
                "target.com",       # 타겟
                "hanjin.co.kr",     # 한진
                "korex.co.kr",      # 대한통운
            ],
            "healthcare_pharma": [
                "greencross.com",   # 녹십자
                "yuhan.co.kr",      # 유한양행
                "donga-st.com",     # 동아제약
                "celltrion.com",    # 셀트리온
                "samsung.com",      # 삼성바이오로직스
                "lgchem.com",       # LG화학(제약부문)
                "pfizer.com",       # 화이자
                "novartis.com",     # 노바티스
                "roche.com",        # 로슈
                "merck.com",        # 머크
                "jnj.com",          # 존슨앤존슨
            ],
            
            # 채용/인사 서비스 추가
            "recruitment": [
                "saramin.co.kr",    # 사람인
                "jobkorea.co.kr",   # 잡코리아
                "incruit.com",      # 인크루트
                "wanted.co.kr",     # 원티드
                "jumpit.co.kr",     # 점핏
                "jobplanet.co.kr",  # 잡플래닛
                "recruiter.co.kr",  # 리크루터
                "indeed.com",       # 인디드
                "linkedin.com",     # 링크드인
                "monster.com",      # 몬스터
            ],
            
            # 기타 분류
            "media_entertainment": [
                "kbs.co.kr",        # KBS
                "mbc.co.kr",        # MBC
                "sbs.co.kr",        # SBS
                "jtbc.co.kr",       # JTBC
                "cnn.com",          # CNN
                "bbc.com",          # BBC
                "netflix.com",      # 넷플릭스
                "disney.com",       # 디즈니
                "hbo.com",          # HBO
                "cj.net",           # CJ ENM
                "boannews.com",     # 보안뉴스
                "pickle.plus",       # 피클플러스
                "tving.com",
            ],
            "food_beverage": [
                "cj.co.kr",         # CJ제일제당
                "hy.co.kr",         # 오뚜기
                "nongshim.com",     # 농심
                "lottechilsung.co.kr", # 롯데칠성
                "coca-cola.com",    # 코카콜라
                "pepsico.com",      # 펩시
                "nestle.com",       # 네슬레
            ],
            "travel_hospitality": [
                "koreanair.com",    # 대한항공
                "asianaairlines.com", # 아시아나항공
                "jejuair.net",      # 제주항공
                "jinair.com",       # 진에어
                "hilton.com",       # 힐튼
                "marriott.com",     # 메리어트
                "hyatt.com",        # 하얏트
                "lotte.com",        # 롯데호텔
                "shilla.net",       # 신라호텔
                "expedia.com",      # 익스피디아
                "booking.com",      # 부킹닷컴
            ],
            
            # 비영리
            "ngo_foundation": [
                "unicef.org",       # 유니세프
                "redcross.org",     # 적십자
                "oxfam.org",        # 옥스팜
                "wwf.org",          # 세계자연기금
                "amnesty.org",      # 국제앰네스티
                "greenpeace.org",   # 그린피스
                "or.kr",            # 한국 비영리단체
                "org",              # 비영리단체
            ],
            "religious": [
                "catholic.or.kr",   # 천주교
                "buddhapia.com",    # 불교
                "churchofjesuschrist.org", # 기독교
                "islam.org",        # 이슬람
                "vatican.va",       # 바티칸
            ]
        }
    
    
    def reset_analysis_result(self):
        """분석 결과 초기화"""
        self.analysis_result = {
            "dnssec_status": "unknown",
            "address_verification": "unknown",
            "spf_check": "unknown",
            "dkim_check": "unknown",
            "dmarc_check": "unknown",
            "domain_reputation": "unknown",
            "final_verdict": "unknown",
            "details": {},
            "reasons": []
        }
    
    def parse_email(self, raw_email):
        """이메일 원문을 파싱하여 헤더 정보 추출"""
        try:
            # 이메일 미리보기 로깅
            preview = raw_email[:100] if isinstance(raw_email, bytes) else str(raw_email)[:100]
            logger.info(f"이메일 원문 미리보기: {preview}...")
            
            # 문자열인 경우 바이트로 변환
            if isinstance(raw_email, str):
                logger.info("문자열을 바이트로 변환합니다.")
                raw_email = raw_email.encode('utf-8')
            
            # 파일 객체인 경우 읽기
            if hasattr(raw_email, 'read'):
                logger.info("파일 객체에서 내용을 읽습니다.")
                raw_email = raw_email.read()
            
            # 이메일이 비어있는지 확인
            if not raw_email:
                logger.error("이메일 내용이 비어 있습니다.")
                return None
                
            # BytesParser를 사용하여 바이트 데이터를 직접 파싱
            logger.info("BytesParser로 이메일 파싱을 시도합니다.")
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            logger.info(f"이메일 파싱 성공: {len(msg.keys())} 헤더 발견")
            return msg
        except Exception as e:
            logger.error(f"이메일 파싱 오류: {e}")
            logger.error(f"상세 오류: {traceback.format_exc()}")
            return None
    
    def extract_headers(self, msg, header_name):
        """지정된 헤더 값들 추출"""
        headers = msg.get_all(header_name, [])
        logger.info(f"발견된 {header_name} 헤더 수: {len(headers)}")
        
        for header in headers:
            logger.info(f"{header_name} 헤더: {header}")
        
        return headers
    
    def analyze_header_chain(self, msg):
        """이메일 헤더 체인 분석"""
        # 헤더 전체 목록
        header_list = list(msg.keys())
        logger.info(f"이메일에 포함된 모든 헤더: {header_list}")
    
        # 주요 헤더 체인 분석 (순서대로)
        chain_analysis = {
            "valid_chain": True,
            "suspicious_patterns": []
        }
    
        # 이메일 서비스 제공업체 리스트 및 패턴
        email_providers = ["stibee.com", "mailchimp.com", "sendgrid.net", "amazonses.com", "newsletters.com"]
        email_provider_patterns = [
            r's\d+\.sendmail\d+\.com',  # s숫자.sendmail숫자.com 패턴
            r'sendmail\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}',  # sendmail.도메인.TLD 패턴
            r'c\d+-\d+\.smtp-out\.[a-z0-9-]+\.amazonses\.com',  # AWS SES SMTP 서버 패턴
            r'cos-sender\d+\.navercorp\.com',  # 네이버 메일 서버
            r'ems\d+\.ahnlab.com',  # 안랩 메일 서버
            r'smtp\.[a-zA-Z]+\.kr',  # smtp.도메인.kr
            # 추가 패턴은 여기에 넣을 수 있습니다
        ]
    
        # Received 헤더 분석
        received_headers = self.extract_headers(msg, 'Received')
        if not received_headers:
            chain_analysis["valid_chain"] = False
            chain_analysis["suspicious_patterns"].append("No Received headers found")
    
        # 도메인 추출 (첫 번째 Received)
        technical_sender_domain = None
        if received_headers:
            technical_sender_domain = self.extract_domain_from_received(received_headers)
            if not technical_sender_domain:
                chain_analysis["suspicious_patterns"].append("Failed to extract sender domain")
    
        # Return-Path 분석
        return_paths = self.extract_headers(msg, 'Return-Path')
        return_path_domain = None
        if return_paths:
            return_path_domain = self.extract_domain_from_email(return_paths[0])
        
            # Return-Path와 Received 도메인 비교
            if technical_sender_domain and return_path_domain and technical_sender_domain not in return_path_domain and return_path_domain not in technical_sender_domain:
                chain_analysis["suspicious_patterns"].append(f"Return-Path domain ({return_path_domain}) doesn't match Received domain ({technical_sender_domain})")
        else:
            chain_analysis["suspicious_patterns"].append("No Return-Path header")
    
        # From 헤더 분석
        from_headers = self.extract_headers(msg, 'From')
        from_domain = None
        if from_headers:
            from_domain = self.extract_domain_from_email(from_headers[0])
            logger.info(f"From 헤더 도메인: {from_domain}")
        
            # From과 Received 도메인 비교
            if technical_sender_domain and from_domain and technical_sender_domain not in from_domain and from_domain not in technical_sender_domain:
                # 이메일 제공업체인지 확인
                is_email_provider = False
            
                # 문자열 리스트에서 확인
                if any(provider in technical_sender_domain for provider in email_providers):
                    is_email_provider = True
            
                # 정규식 패턴에서 확인
                if not is_email_provider:
                    for pattern in email_provider_patterns:
                        if re.search(pattern, technical_sender_domain):
                            is_email_provider = True
                            break
            
                # 이메일 제공업체가 아닐 경우 의심스러운 패턴 추가
                if not is_email_provider:
                    chain_analysis["suspicious_patterns"].append(f"From domain ({from_domain}) doesn't match Received domain ({technical_sender_domain})")
        else:
            chain_analysis["suspicious_patterns"].append("No From header")
    
        # 결과 저장
        self.analysis_result["header_chain"] = chain_analysis
        self.analysis_result["technical_sender_domain"] = technical_sender_domain
        self.analysis_result["from_domain"] = from_domain
        self.analysis_result["return_path_domain"] = return_path_domain
    
        # 발신자 도메인 결정 (From 도메인과 기술적 송신 도메인 중 선택)
        actual_sender_domain = None
    
        # 이메일 제공업체인지 확인
        is_email_provider = False
    
        # 문자열 리스트에서 확인
        if technical_sender_domain and any(provider in technical_sender_domain for provider in email_providers):
            is_email_provider = True
    
        # 정규식 패턴에서 확인
        if technical_sender_domain and not is_email_provider:
            for pattern in email_provider_patterns:
                if re.search(pattern, technical_sender_domain):
                    is_email_provider = True
                    break
    
        # 대형 이메일 발송 서비스인 경우 From 도메인 우선
        if from_domain and technical_sender_domain and is_email_provider:
            actual_sender_domain = from_domain
            self.analysis_result["sender_type"] = "marketing"
            logger.info(f"마케팅/뉴스레터 이메일 감지: 발송 서비스 {technical_sender_domain}, 발신자 {from_domain}")
        # 그렇지 않은 경우 기술적 송신 도메인 우선
        else:
            actual_sender_domain = technical_sender_domain
    
        self.analysis_result["sender_domain"] = actual_sender_domain
    
        logger.info(f"헤더 체인 분석 결과: {chain_analysis}")
        return actual_sender_domain
    
    def extract_domain_from_received(self, received_headers):
        """Received 헤더에서 from 도메인 추출"""
        for header in received_headers:
            # from 다음에 오는 도메인 찾기
            match = re.search(r'from\s+([^\s]+)', header)
            if match:
                domain = match.group(1)
                # 도메인에서 불필요한 문자 제거
                domain = domain.strip('()<>[]{}')
                logger.info(f"Received 헤더에서 추출한 도메인: {domain}")
                
                # IP 주소가 포함되었는지 확인
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header)
                if ip_match:
                    ip = ip_match.group(1)
                    logger.info(f"Received 헤더에서 추출한 IP: {ip}")
                    self.analysis_result["details"]["sender_ip"] = ip
                
                return domain
        return None
    
    def extract_domain_from_email(self, email_str):
        """이메일 주소에서 도메인 추출"""
        try:
            # 이메일 주소 형식(user@domain.com)에서 도메인 추출
            match = re.search(r'[\w\.-]+@([\w\.-]+)', str(email_str))
            if match:
                return match.group(1)
            return None
        except Exception as e:
            logger.error(f"이메일에서 도메인 추출 오류: {e}")
            return None
    
    def check_whois_info(self, domain):
        """WHOIS 정보 확인 및 도메인 등록 정보 검증"""
        try:
            logger.info(f"WHOIS 정보 조회: {domain}")
            w = whois.whois(domain)
            
            # WHOIS 응답 형식은 라이브러리/서버마다 다를 수 있으므로 안전하게 처리
            domain_info = {}
            
            # 도메인 이름
            if hasattr(w, 'domain_name'):
                domain_info["domain_name"] = w.domain_name
            else:
                domain_info["domain_name"] = domain
            
            # 등록자
            if hasattr(w, 'registrar'):
                domain_info["registrar"] = w.registrar
            elif hasattr(w, 'org') or hasattr(w, 'organization'):
                domain_info["registrar"] = getattr(w, 'org', '') or getattr(w, 'organization', '')
            else:
                domain_info["registrar"] = "Unknown"
            
            # 생성 날짜
            if hasattr(w, 'creation_date'):
                domain_info["creation_date"] = w.creation_date
            else:
                domain_info["creation_date"] = "Unknown"
            
            # 만료 날짜
            if hasattr(w, 'expiration_date'):
                domain_info["expiration_date"] = w.expiration_date
            else:
                domain_info["expiration_date"] = "Unknown"
            
            # 주소
            if hasattr(w, 'address'):
                domain_info["registrant_address"] = w.address
            else:
                domain_info["registrant_address"] = "Unknown"
            
            # 연락처
            if hasattr(w, 'emails'):
                domain_info["contact_emails"] = w.emails
            else:
                domain_info["contact_emails"] = "Unknown"
            
            self.analysis_result["details"]["domain_info"] = domain_info
            
            # DNSSEC 확인
            if hasattr(w, 'dnssec') and w.dnssec and ('signed' in str(w.dnssec).lower() or 'yes' in str(w.dnssec).lower()):
                self.analysis_result["dnssec_status"] = "signed"
            else:
                self.analysis_result["dnssec_status"] = "unsigned"
                self.analysis_result["reasons"].append("DNSSEC 서명이 확인되지 않음")
            
            # 도메인 등록 기간 확인 (최근 등록된 도메인은 의심스러울 수 있음)
            if domain_info.get("creation_date") and domain_info["creation_date"] != "Unknown":
                import datetime
                if isinstance(domain_info["creation_date"], list):
                    creation_date = domain_info["creation_date"][0]
                else:
                    creation_date = domain_info["creation_date"]
                
                if isinstance(creation_date, datetime.datetime):
                    domain_age_days = (datetime.datetime.now() - creation_date).days
                    domain_info["domain_age_days"] = domain_age_days
                    
                    if domain_age_days < 30:
                        self.analysis_result["domain_reputation"] = "suspicious"
                        self.analysis_result["reasons"].append(f"도메인이 최근에 등록됨 ({domain_age_days}일 전)")
                    else:
                        self.analysis_result["domain_reputation"] = "established"
            
            # 주소 검증 (간단한 검증)
            address = domain_info.get("registrant_address", "")
            if address and address != "Unknown" and len(address) > 5:
                self.analysis_result["address_verification"] = "verified"
            else:
                self.analysis_result["address_verification"] = "failed"
                self.analysis_result["reasons"].append("등록자 주소 정보가 불충분함")
                
            logger.info(f"WHOIS 정보 분석 완료: {domain}")
            return w
        except Exception as e:
            logger.error(f"WHOIS 정보 조회 오류: {e}")
            logger.error(traceback.format_exc())
            # 오류 발생 시에도 기본값 설정
            self.analysis_result["dnssec_status"] = "error"
            self.analysis_result["address_verification"] = "error"
            self.analysis_result["reasons"].append(f"WHOIS 정보 조회 중 오류 발생: {str(e)}")
            return None
    
    def check_dns_records(self, domain):
        """도메인의 DNS 레코드 전체 검증"""
        try:
            # 이미 분석한 도메인이면 건너뛰기
            if domain in self.domains_analyzed:
                logger.info(f"이미 분석한 도메인 건너뛰기: {domain}")
                return
            
            self.domains_analyzed.add(domain)
            logger.info(f"DNS 레코드 검사: {domain}")
            
            # A 레코드 검사
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                ip_addresses = [rdata.address for rdata in a_records]
                logger.info(f"A 레코드: {ip_addresses}")
                
                # IP 주소 평판 검사 (간단한 구현)
                for ip in ip_addresses:
                    # 내부 IP 또는 예약된 IP 범위 확인
                    if self.is_private_ip(ip):
                        self.analysis_result["reasons"].append(f"사설 IP 사용: {ip}")
            except Exception as e:
                logger.warning(f"A 레코드 조회 실패: {e}")
            
            # MX 레코드 검사
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_servers = [str(rdata.exchange) for rdata in mx_records]
                logger.info(f"MX 레코드: {mx_servers}")
                
                # MX 서버 도메인이 원래 도메인과 일치하는지 확인
                for mx_server in mx_servers:
                    if domain not in mx_server and not any(mx_server.endswith('.' + part) for part in domain.split('.')):
                        logger.warning(f"MX 서버 도메인이 원본 도메인과 일치하지 않음: {mx_server}")
            except Exception as e:
                logger.warning(f"MX 레코드 조회 실패: {e}")
            
            # TXT 레코드로 SPF 확인 (기본 도메인)
            self.check_spf_record(domain)
            
            # 상위 도메인에 대한 SPF 확인
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                parent_domain = '.'.join(domain_parts[1:])
                logger.info(f"상위 도메인 SPF 확인: {parent_domain}")
                self.check_spf_record(parent_domain)
            
            logger.info(f"DNS 레코드 분석 완료: {domain}")
            return True
        except Exception as e:
            logger.error(f"DNS 레코드 검사 오류: {e}")
            logger.error(traceback.format_exc())
            self.analysis_result["reasons"].append(f"DNS 레코드 검사 중 오류: {str(e)}")
            return False
    
    def is_private_ip(self, ip):
        """IP가 사설 범위에 속하는지 확인"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except Exception:
            return False
    
    def check_spf_record(self, domain):
        """도메인의 SPF 레코드 확인"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_record = rdata.to_text()
                
                # SPF 레코드 검색
                if "v=spf1" in txt_record:
                    logger.info(f"SPF 레코드 발견: {txt_record}")
                    
                    # 모든 허용 메커니즘 검사
                    self.extract_spf_mechanisms(txt_record, domain)
                    
                    # IP 주소 추출 (ip4: 형식)
                    ip_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', txt_record)
                    for ip in ip_matches:
                        self.dig_ip_list.append(ip)
                    
                    # include 도메인 추출
                    include_matches = re.findall(r'include:([^\s]+)', txt_record)
                    for include_domain in include_matches:
                        # 재귀적으로 include 도메인의 TXT 레코드 확인
                        logger.info(f"SPF include 도메인 검사: {include_domain}")
                        self.check_spf_record(include_domain)
                    
                    # SPF 레코드에 -all 또는 ~all과 같은 엄격한 정책이 있는지 확인
                    if re.search(r'[-~]all', txt_record):
                        logger.info("엄격한 SPF 정책 발견 (-all 또는 ~all)")
                    else:
                        logger.warning("약한 SPF 정책: ?all 또는 +all이 사용되었거나 all 지시자 누락")
                        self.analysis_result["reasons"].append("약한 SPF 정책 사용")
            
            return True
        except dns.resolver.NoAnswer:
            logger.warning(f"{domain}에 대한 TXT 레코드 없음")
            self.analysis_result["reasons"].append(f"{domain}에 SPF 레코드가 없음")
            return False
        except Exception as e:
            logger.error(f"SPF 레코드 조회 오류: {e}")
            return False
    
    def extract_spf_mechanisms(self, spf_record, domain):
        """SPF 레코드에서 모든 메커니즘 추출 및 분석"""
        mechanisms = re.findall(r'[\+\-\~\?]?(?:ip4|ip6|a|mx|include|exists|redirect|exp):[^\s]+', spf_record)
        logger.info(f"추출된 SPF 메커니즘: {mechanisms}")
        
        # '+all'과 같은 위험한 메커니즘 확인
        if "+all" in spf_record:
            logger.warning(f"도메인 {domain}에 위험한 SPF 설정 발견: +all")
            self.analysis_result["reasons"].append(f"위험한 SPF 설정: +all (모든 발신자 허용)")
    
    def extract_spf_ip(self, msg):
        """Received-SPF 헤더에서 IP 주소 추출 및 검증"""
        try:
            spf_header = msg.get('Received-SPF')
            if not spf_header:
                logger.warning("Received-SPF 헤더가 없습니다.")
                self.analysis_result["spf_check"] = "missing"
                self.analysis_result["reasons"].append("Received-SPF 헤더 없음")
                return False
            
            logger.info(f"Received-SPF 헤더: {spf_header}")
            
            # SPF 검사 결과 확인
            result_match = re.search(r'^(\w+)', spf_header)
            if result_match:
                spf_result = result_match.group(1).lower()
                logger.info(f"SPF 검사 결과: {spf_result}")
                
                if spf_result not in ['pass', 'pass,']:
                    self.analysis_result["reasons"].append(f"SPF 검사 실패: {spf_result}")
            
            # designates 다음에 오는 IP 주소 추출
            match = re.search(r'designates\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', spf_header)
            if match:
                ip = match.group(1)
                self.spf_ip_list.append(ip)
                logger.info(f"SPF IP 추출 완료: {ip}")
                
                # client-ip와 비교
                client_ip_match = re.search(r'client-ip=(\d+\.\d+\.\d+\.\d+)', spf_header)
                if client_ip_match:
                    client_ip = client_ip_match.group(1)
                    logger.info(f"client-ip: {client_ip}")
                    
                    if client_ip != ip.split('/')[0]:
                        logger.warning(f"designates IP와 client-ip 불일치: {ip} vs {client_ip}")
                        self.analysis_result["reasons"].append(f"SPF IP 불일치: {ip} vs {client_ip}")
                
                return True
            else:
                logger.warning("SPF 헤더에서 IP 주소를 찾을 수 없습니다.")
                self.analysis_result["spf_check"] = "no_ip"
                self.analysis_result["reasons"].append("SPF 헤더에서 IP 주소 누락")
                return False
        except Exception as e:
            logger.error(f"SPF IP 추출 오류: {e}")
            logger.error(traceback.format_exc())
            self.analysis_result["spf_check"] = "error"
            self.analysis_result["reasons"].append(f"SPF IP 추출 중 오류: {str(e)}")
            return False
    
    def compare_ip_lists(self):
        """추출한 IP 리스트와 SPF IP 리스트 비교"""
        try:
            if not self.spf_ip_list:
                logger.warning("SPF IP 리스트가 비어 있습니다.")
                self.analysis_result["spf_check"] = "missing"
                self.analysis_result["reasons"].append("SPF 발신자 IP 정보 누락")
                return False
                
            if not self.dig_ip_list:
                logger.warning("DIG IP 리스트가 비어 있습니다.")
                self.analysis_result["spf_check"] = "no_reference"
                self.analysis_result["reasons"].append("DNS에서 SPF IP 범위 정보 없음")
                return False
        
            # IP 네트워크 비교 (CIDR 형식 지원)
            match_found = False
            matching_ips = []
        
            for spf_ip in self.spf_ip_list:
                try:
                    spf_network = ipaddress.ip_network(spf_ip, strict=False)
                
                    for dig_ip in self.dig_ip_list:
                        try:
                            dig_network = ipaddress.ip_network(dig_ip, strict=False)
                        
                            # 네트워크가 겹치는지 확인
                            if (spf_network.overlaps(dig_network) or 
                                dig_network.overlaps(spf_network) or
                                self.check_ip_in_network(spf_ip, dig_ip)):
                                match_found = True
                                matching_ips.append((spf_ip, dig_ip))
                        except ValueError as e:
                            logger.warning(f"IP 비교 오류 (dig): {dig_ip} - {e}")
                except ValueError as e:
                    logger.warning(f"IP 비교 오류 (spf): {spf_ip} - {e}")
        
            if match_found:
                logger.info(f"IP 리스트 비교: 일치 - {matching_ips}")
                self.analysis_result["spf_check"] = "match"
                self.analysis_result["details"]["matching_ips"] = matching_ips
                return True
            else:
                logger.warning("IP 리스트 비교: 불일치")
                self.analysis_result["spf_check"] = "mismatch"
                self.analysis_result["reasons"].append("발신자 IP가 SPF에 허용된 범위에 없음")
                return False
        except Exception as e:
            logger.error(f"IP 리스트 비교 오류: {e}")
            logger.error(traceback.format_exc())
            self.analysis_result["spf_check"] = "error"
            self.analysis_result["reasons"].append(f"IP 비교 중 오류: {str(e)}")
            return False
    
    def check_ip_in_network(self, spf_ip, dig_ip):
        """IP가 네트워크에 포함되는지 확인"""
        try:
            # CIDR 형식이 아닌 경우 처리
            if '/' not in spf_ip:
                spf_ip = f"{spf_ip}/32"
            if '/' not in dig_ip:
                dig_ip = f"{dig_ip}/32"
                
            spf_net = ipaddress.ip_network(spf_ip, strict=False)
            dig_net = ipaddress.ip_network(dig_ip, strict=False)
            
            # 단일 IP인 경우
            if spf_net.prefixlen == 32 and dig_net.prefixlen == 32:
                return str(spf_net.network_address) == str(dig_net.network_address)
            
            return (spf_net.overlaps(dig_net) or 
                    dig_net.overlaps(spf_net) or
                    spf_net.subnet_of(dig_net) or 
                    dig_net.subnet_of(spf_net))
        except Exception as e:
            logger.warning(f"IP 네트워크 비교 오류: {e}")
            return False
    
    def analyze_dkim_dmarc(self, msg):
        """DKIM 및 DMARC 정보 분석"""
        # Authentication-Results 헤더 확인
        auth_results = msg.get('Authentication-Results', '')
        
        if auth_results:
            logger.info(f"Authentication-Results: {auth_results}")
            
            # DKIM 결과
            dkim_match = re.search(r'dkim=(\w+)', auth_results)
            if dkim_match:
                dkim_result = dkim_match.group(1).lower()
                self.analysis_result["dkim_check"] = dkim_result
                
                if dkim_result not in ["pass", "none"]:  # none은 오류로 간주하지 않음
                    self.analysis_result["reasons"].append(f"DKIM 검증 실패: {dkim_result}")
            else:
                self.analysis_result["dkim_check"] = "missing"
                # DKIM 서명 부재를 심각한 문제로 보지 않음 (정상 이메일도 DKIM 없는 경우 많음)
                # self.analysis_result["reasons"].append("DKIM 서명 없음")
            
            # DMARC 결과
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1).lower()
                self.analysis_result["dmarc_check"] = dmarc_result
                
                if dmarc_result not in ["pass", "none"]:  # none은 오류로 간주하지 않음
                    self.analysis_result["reasons"].append(f"DMARC 검증 실패: {dmarc_result}")
            else:
                self.analysis_result["dmarc_check"] = "missing"
                # DMARC 정책 부재를 심각한 문제로 보지 않음 (정상 이메일도 DMARC 없는 경우 많음)
                # self.analysis_result["reasons"].append("DMARC 정책 없음")
        else:
            logger.warning("Authentication-Results 헤더 없음")
            self.analysis_result["dkim_check"] = "unknown"
            self.analysis_result["dmarc_check"] = "unknown"
            # Authentication-Results 헤더가 없어도 심각한 문제로 보지 않음 (일부 서버는 추가하지 않음)
            # self.analysis_result["reasons"].append("인증 결과 헤더 없음")
        
        # DKIM-Signature 헤더 직접 확인
        dkim_sig = msg.get('DKIM-Signature', '')
        if dkim_sig:
            logger.info("DKIM-Signature 헤더 발견")
            
            # 서명 도메인 확인
            domain_match = re.search(r'd=([^;]+)', dkim_sig)
            if domain_match:
                dkim_domain = domain_match.group(1).strip()
                logger.info(f"DKIM 서명 도메인: {dkim_domain}")
                
                # 발신자 도메인과 DKIM 도메인 비교 (하위 도메인 허용)
                sender_domain = self.analysis_result.get("sender_domain")
                if sender_domain and not (dkim_domain in sender_domain or sender_domain in dkim_domain or 
                                         sender_domain.endswith(f".{dkim_domain}") or 
                                         any(d.endswith(f".{dkim_domain}") for d in sender_domain.split('.'))):
                    logger.warning(f"DKIM 도메인과 발신자 도메인 불일치: {dkim_domain} vs {sender_domain}")
                    self.analysis_result["reasons"].append(f"DKIM 도메인 불일치: {dkim_domain}")
        
        # ARC-Authentication-Results 헤더 확인 (DKIM/DMARC 정보 추가 소스)
        arc_auth = msg.get('ARC-Authentication-Results', '')
        if arc_auth:
            logger.info(f"ARC-Authentication-Results: {arc_auth}")
            
            # DKIM 결과가 없을 경우 ARC에서 확인
            if self.analysis_result["dkim_check"] == "unknown" or self.analysis_result["dkim_check"] == "missing":
                dkim_match = re.search(r'dkim=(\w+)', arc_auth)
                if dkim_match:
                    dkim_result = dkim_match.group(1).lower()
                    self.analysis_result["dkim_check"] = f"arc_{dkim_result}"
                    
                    if dkim_result not in ["pass", "none"]:
                        self.analysis_result["reasons"].append(f"ARC DKIM 검증 실패: {dkim_result}")
            
            # DMARC 결과가 없을 경우 ARC에서 확인
            if self.analysis_result["dmarc_check"] == "unknown" or self.analysis_result["dmarc_check"] == "missing":
                dmarc_match = re.search(r'dmarc=(\w+)', arc_auth)
                if dmarc_match:
                    dmarc_result = dmarc_match.group(1).lower()
                    self.analysis_result["dmarc_check"] = f"arc_{dmarc_result}"
                    
                    if dmarc_result not in ["pass", "none"]:
                        self.analysis_result["reasons"].append(f"ARC DMARC 검증 실패: {dmarc_result}")
    
    def analyze_arc_headers(self, msg):
        """ARC(Authenticated Received Chain) 헤더 분석"""
        arc_seal = msg.get('ARC-Seal', '')
        arc_msg_sig = msg.get('ARC-Message-Signature', '')
        arc_auth = msg.get('ARC-Authentication-Results', '')
    
        if arc_seal and arc_msg_sig and arc_auth:
            logger.info("ARC 헤더 발견 - 이메일이 전달된 것으로 보임")
        
            # ARC 체인 값 확인 - cv=none은 정상값임
            cv_match = re.search(r'cv=(\w+)', arc_seal)
            if cv_match:
                cv_value = cv_match.group(1)
                logger.info(f"ARC 체인 검증 결과: {cv_value}")
            
                # cv=none은 ARC 체인의 첫 번째 링크로 오류가 아님
                if cv_value != 'pass' and cv_value != 'none':
                    self.analysis_result["reasons"].append(f"ARC 체인 검증 실패: {cv_value}")
        
            # ARC Authentication 결과 확인
            if 'spf=pass' in arc_auth:
                logger.info("ARC 인증 결과: SPF 통과")
                # DKIM이 없는 것은 오류가 아님, 많은 메일에서 DKIM을 사용하지 않음
            else:
                logger.warning("ARC 인증 결과에 SPF 실패 항목이 있음")
                self.analysis_result["reasons"].append("원본 이메일의 SPF 인증 실패 (ARC 헤더 기준)")

    
    def analyze_sender_organization(self, domain):
        """발신자 도메인을 기반으로 기관 유형 분석 (세분화 버전)"""
        if not domain:
            logger.warning("기관 분석: 도메인 정보 없음")
            self.analysis_result["organization_type"] = "unknown"
            self.analysis_result["organization_subtype"] = "unknown"
            return "unknown"
        
        # 도메인을 소문자로 변환
        domain = domain.lower()
        logger.info(f"기관 분석: 도메인 {domain} 검사")
        
        # 기관 대분류 및 소분류 초기화
        main_type = "unknown"
        sub_type = "unknown"
        
        # 각 기관 유형별 확인
        for org_type, domains in self.org_types.items():
            # 정확히 일치하는 경우
            if domain in domains:
                logger.info(f"기관 분석: {domain}은 '{org_type}' 유형으로 정확히 일치")
                sub_type = org_type
                break
                
            # 서브도메인 또는 도메인 끝부분 일치 확인
            for pattern in domains:
                if domain.endswith('.' + pattern) or domain == pattern:
                    logger.info(f"기관 분석: {domain}은 '{org_type}' 유형의 패턴 {pattern}과 일치")
                    sub_type = org_type
                    break
            
            if sub_type != "unknown":
                break
        
        # 서브타입이 결정되었으면 메인 카테고리 결정
        if sub_type != "unknown":
            # 공공기관 분류
            if sub_type in ["government", "military", "public_corporation", "local_government"]:
                main_type = "public"
            
            # 금융기관 분류
            elif sub_type in ["bank", "insurance", "securities", "card"]:
                main_type = "financial"
            
            # 교육기관 분류
            elif sub_type in ["university", "school", "research"]:
                main_type = "education"
            
            # IT/기술 분류
            elif sub_type in ["it_software", "telecom"]:
                main_type = "technology"
            
            # 제조/산업 분류
            elif sub_type in ["manufacturing", "electronics", "automotive"]:
                main_type = "manufacturing"
            
            # 유통/서비스 분류
            elif sub_type in ["retail_logistics", "food_beverage", "travel_hospitality", "recruitment"]:
                main_type = "service"
            
            # 미디어/엔터테인먼트
            elif sub_type in ["media_entertainment"]:
                main_type = "media"
            
            # 의료/제약
            elif sub_type in ["healthcare_pharma"]:
                main_type = "healthcare"
            
            # 비영리
            elif sub_type in ["ngo_foundation", "religious"]:
                main_type = "nonprofit"
        
        # TLD 기반 추가 분석 (서브타입이 여전히 불명확한 경우)
        if sub_type == "unknown":
            tld = domain.split('.')[-1]
            
            # 한국 도메인 세부 분석
            if domain.endswith('.go.kr'):
                main_type = "public"
                sub_type = "government"
            elif domain.endswith('.mil.kr') or domain.endswith('.mil'):
                main_type = "public"
                sub_type = "military"
            elif domain.endswith('.ac.kr') or tld == 'edu':
                main_type = "education"
                sub_type = "university"
            elif domain.endswith('.hs.kr'):
                main_type = "education"
                sub_type = "school"
            elif domain.endswith('.re.kr'):
                main_type = "education"
                sub_type = "research"
            elif domain.endswith('.or.kr') or tld == 'org':
                main_type = "nonprofit"
                sub_type = "ngo_foundation"
            elif domain.endswith('.co.kr') or tld == 'com':
                main_type = "commercial"
                sub_type = "general_business"
            elif domain.endswith('.ne.kr') or tld == 'net':
                main_type = "technology"
                sub_type = "network_provider"
        
        # From 헤더의 표시 이름으로 추가 분석
        if main_type == "unknown" and hasattr(self, 'current_email'):
            from_header = self.current_email.get('From', '')
            
            # 표시 이름 추출 (예: "신한은행" <no-reply@shinhan.com>)
            display_name_match = re.search(r'"([^"]+)"', from_header) or re.search(r'([^<]+)<', from_header)
            if display_name_match:
                display_name = display_name_match.group(1).strip().lower()
                
                # 표시 이름에서 기관 유형 힌트 찾기
                bank_keywords = ['은행', '뱅크', 'bank', '금융', '카드', 'card']
                insurance_keywords = ['보험', '생명', '화재', 'insurance', 'life']
                government_keywords = ['정부', '시청', '구청', '군청', '공단', '국세', '세무서', '행정']
                military_keywords = ['군', '국방', '육군', '해군', '공군']
                education_keywords = ['대학교', '학교', '대학', '교육', '유치원', '초등학교', '중학교', '고등학교', 'university']
                it_keywords = ['소프트웨어', '정보기술', '컴퓨터', '시스템', '솔루션']
                telecom_keywords = ['통신', '텔레콤', '모바일', '네트워크']
                healthcare_keywords = ['병원', '의료', '제약', '약품', '헬스케어', '의원', '클리닉']
                recruitment_keywords = ['사람인', '잡코리아', '채용', '구인', '구직', '인사', '인크루트', '원티드', '취업', '일자리']
                
                if any(keyword in display_name for keyword in bank_keywords):
                    main_type = "financial"
                    sub_type = "bank"
                elif any(keyword in display_name for keyword in insurance_keywords):
                    main_type = "financial"
                    sub_type = "insurance"
                elif any(keyword in display_name for keyword in government_keywords):
                    main_type = "public"
                    sub_type = "government"
                elif any(keyword in display_name for keyword in military_keywords):
                    main_type = "public"
                    sub_type = "military"
                elif any(keyword in display_name for keyword in education_keywords):
                    main_type = "education"
                    sub_type = "university" if "대학" in display_name else "school"
                elif any(keyword in display_name for keyword in it_keywords):
                    main_type = "technology"
                    sub_type = "it_software"
                elif any(keyword in display_name for keyword in telecom_keywords):
                    main_type = "technology"
                    sub_type = "telecom"
                elif any(keyword in display_name for keyword in healthcare_keywords):
                    main_type = "healthcare"
                    sub_type = "healthcare_pharma"
                elif any(keyword in display_name for keyword in recruitment_keywords):
                    main_type = "service"
                    sub_type = "recruitment"
        
        # saramin.co.kr 특별 처리 (채용 서비스)
        if "saramin.co.kr" in domain:
            main_type = "service" 
            sub_type = "recruitment"
        
        # 결과 저장
        self.analysis_result["organization_type"] = main_type
        self.analysis_result["organization_subtype"] = sub_type
        
        logger.info(f"기관 분석 결과: 대분류={main_type}, 소분류={sub_type}")
        return main_type
    
    def determine_final_verdict(self):
        """철저한 분석 결과를 바탕으로 최종 판정"""
        try:
            # 초기 상태 설정 (모두 통과할 경우)
            self.analysis_result["final_verdict"] = "pass"
        
            # 1. SPF 검증 실패 시 의심 또는 차단
            if self.analysis_result["spf_check"] == "mismatch":
                self.analysis_result["final_verdict"] = "suspicious"
                self.analysis_result["reasons"].append("SPF 불일치 - 발신자 도메인과 허용된 IP 목록 불일치")
            
                # 마케팅 이메일이나 중요 기관의 경우 SPF 불일치는 더 심각함
                if self.analysis_result.get("sender_type") == "marketing" or \
                    self.analysis_result.get("organization_type") in ["public", "financial"]:
                    self.analysis_result["final_verdict"] = "block"
        
            # 2. 의심 요소 수 확인 - 하위 도메인 SPF 누락과 주소 정보 부재는 경미한 문제로 취급
            suspicion_count = 0
            critical_issues = []
            minor_issues = ["등록자 주소 정보가 불충분함", "SPF 레코드가 없음", "DKIM 서명 없음", "DMARC 정책 없음", "인증 결과 헤더 없음"]
        
            for reason in self.analysis_result["reasons"]:
                if not any(minor in reason for minor in minor_issues):
                    suspicion_count += 1
                    critical_issues.append(reason)
        
            # 3. 심각한 인증 실패 여부 확인
            auth_failures = 0
            if self.analysis_result["spf_check"] == "mismatch":  # 불일치만 문제로 간주
                auth_failures += 1
            if self.analysis_result["dkim_check"] == "fail":     # fail만 문제로 간주
                auth_failures += 1
            if self.analysis_result["dmarc_check"] == "fail":    # fail만 문제로 간주
                auth_failures += 1
        
            # 4. 결정적인 문제가 있을 때만 판정 변경
            if auth_failures > 0 or suspicion_count > 0:
                if auth_failures >= 2 or suspicion_count >= 2:
                    self.analysis_result["final_verdict"] = "suspicious"
                
                    # 군사/정부 기관의 경우, 실제 메일 서버 도메인과 표시 도메인이 같은 영역이면 사칭 가능성 낮음
                    if self.analysis_result.get("organization_subtype") in ["military", "government"]:
                        tech_domain = self.analysis_result.get("technical_sender_domain", "")
                        from_domain = self.analysis_result.get("from_domain", "")
                    
                        if tech_domain and from_domain and \
                        (tech_domain.endswith(from_domain) or from_domain.endswith(tech_domain) or \
                            any(both.endswith(".mil.kr") for both in [tech_domain, from_domain]) or \
                            any(both.endswith(".go.kr") for both in [tech_domain, from_domain])):
                        
                            # SPF가 일치하면 군사/정부 도메인은 통과시킴
                            if self.analysis_result["spf_check"] == "match":
                                self.analysis_result["final_verdict"] = "pass"
                                logger.info("군사/정부 기관 도메인이며 SPF 일치: 판정 완화")
        
            # 5. 최종 판정에 따라 알림 메시지 설정
            if "organization_type" in self.analysis_result:
                org_type = self.analysis_result["organization_type"]
                org_subtype = self.analysis_result.get("organization_subtype", "unknown")
            
                if org_type in ["public", "financial"] or org_subtype in ["military", "government", "bank"]:
                    self.analysis_result["warning_level"] = "high"
                
                    if self.analysis_result["final_verdict"] == "suspicious":
                        org_name = org_subtype if org_subtype != "unknown" else org_type
                        # 판정이 pass에서 suspicious로 변경된 경우만 "사칭" 용어 사용
                        if auth_failures > 0 or suspicion_count >= 2:
                            self.analysis_result["notice"] = f"주의: 이 이메일은 {org_name} 유형 기관을 사칭하는 것으로 의심됩니다. 철저한 검증이 필요합니다."
                        else:
                            self.analysis_result["notice"] = f"주의: 이 이메일은 {org_name} 유형 기관에서 왔으나 일부 검증에 실패했습니다. 확인이 필요합니다."
                    elif self.analysis_result["final_verdict"] == "block":
                        org_name = org_subtype if org_subtype != "unknown" else org_type
                        self.analysis_result["notice"] = f"경고: 이 이메일은 {org_name} 유형 기관을 사칭하는 사기성 메일일 가능성이 높습니다."
                    elif self.analysis_result["final_verdict"] == "pass":
                        org_name = org_subtype if org_subtype != "unknown" else org_type
                        self.analysis_result["notice"] = f"참고: 이 이메일은 {org_name} 유형 기관에서 발송된 것으로 확인됩니다."
        
                # 6. 최종 판정이 'pass'인 경우 의심 이유 목록 비우기
            if self.analysis_result["final_verdict"] == "pass":
                self.analysis_result["reasons"] = []
        
            return self.analysis_result["final_verdict"]
        except Exception as e:
            logger.error(f"최종 판정 중 오류 발생: {e}")
            logger.error(traceback.format_exc())
            self.analysis_result["final_verdict"] = "error"
            self.analysis_result["reasons"].append(f"판정 오류: {str(e)}")
            return "error"
        
    def analyze_email(self, raw_email):
        """이메일 분석 메인 함수 - 모든 검증 단계 실행"""
        self.reset_analysis_result()  # 분석 결과 초기화
        self.spf_ip_list = []  # IP 목록 초기화
        self.dig_ip_list = []  # DNS IP 목록 초기화
        self.domains_analyzed = set()  # 분석한 도메인 초기화
        
        try:
            # 1. 이메일 파싱
            msg = self.parse_email(raw_email)
            if not msg:
                self.analysis_result["final_verdict"] = "error"
                self.analysis_result["reason"] = "이메일 파싱 실패"
                return self.analysis_result
            
            # 이메일 객체 저장 (분석용)
            self.current_email = msg
            
            # 2. 헤더 체인 분석 및 발신자 도메인 추출
            sender_domain = self.analyze_header_chain(msg)
            if not sender_domain:
                self.analysis_result["final_verdict"] = "error"
                self.analysis_result["reason"] = "발신자 도메인 추출 실패"
                return self.analysis_result
            
            # 3. 발신자 기관 유형 분석
            self.analyze_sender_organization(sender_domain)
            
            # 4. WHOIS 정보 확인
            self.check_whois_info(sender_domain)
            
            # 5. DNS 레코드 전체 검증
            self.check_dns_records(sender_domain)
            
            # 6. Received-SPF 헤더에서 IP 추출
            self.extract_spf_ip(msg)
            
            # 7. DNS에서 추출한 IP와 SPF 헤더의 IP 비교
            self.compare_ip_lists()
            
            # 8. DKIM 및 DMARC 분석
            self.analyze_dkim_dmarc(msg)
            
            # 9. ARC 헤더 분석 (전달된 이메일)
            self.analyze_arc_headers(msg)
            
            # 10. 최종 판정
            self.determine_final_verdict()
            
            logger.info(f"최종 분석 결과: {self.analysis_result['final_verdict']}")
            if "organization_type" in self.analysis_result:
                logger.info(f"기관 유형: {self.analysis_result['organization_type']}")
            logger.info(f"이유: {self.analysis_result['reasons']}")
            
            return self.analysis_result
        except Exception as e:
            logger.error(f"이메일 분석 중 오류 발생: {e}")
            logger.error(traceback.format_exc())
            self.analysis_result["final_verdict"] = "error"
            self.analysis_result["reason"] = f"분석 오류: {str(e)}"
            return self.analysis_result

def install_requirements():
    """필요한 패키지 설치"""
    try:
        import pip
        print("필요한 패키지 설치 중...")
        pip.main(['install', 'python-whois', 'dnspython'])
        print("패키지 설치 완료")
        return True
    except Exception as e:
        print(f"패키지 설치 중 오류 발생: {e}")
        print("수동으로 다음 패키지를 설치해주세요: python-whois, dnspython")
        print("pip install python-whois dnspython")
        return False

# 테스트용 샘플 이메일 생성 함수
def create_sample_email():
    """테스트용 샘플 이메일 생성"""
    sample_email = """Return-Path: <sender@example.com>
Received: from mail.example.com (mail.example.com [192.168.1.1])
    by receiver.example.org (Postfix) with ESMTP id 1234ABCD
    for <recipient@example.org>; Mon, 25 Mar 2025 10:00:00 +0000 (UTC)
Received-SPF: pass (receiver.example.org: domain of sender@example.com designates 192.168.1.1 as permitted sender)
Authentication-Results: receiver.example.org; spf=pass smtp.mailfrom=sender@example.com; dkim=pass (signature verified) header.d=example.com; dmarc=pass action=none header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;
    h=from:to:subject:date:message-id:mime-version;
    bh=Base64Hash=; b=Base64Signature=
From: "Sender" <sender@example.com>
To: "Recipient" <recipient@example.org>
Subject: Test Email for Analysis
Date: Mon, 25 Mar 2025 10:00:00 +0000
Message-ID: <unique-id@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

This is a test email for header analysis.
"""
    with open("sample_email.eml", "w", encoding="utf-8") as f:
        f.write(sample_email)
    print("샘플 이메일이 'sample_email.eml' 파일로 생성되었습니다.")
    return "sample_email.eml"

# 사용 예시
def main():
    try:
        # 필요한 패키지 설치 확인
        try:
            import whois
            import dns.resolver
        except ImportError:
            install_requirements()
            # 다시 import 시도
            try:
                import whois
                import dns.resolver
            except ImportError:
                print("필요한 패키지가 설치되지 않았습니다. 수동으로 설치해주세요.")
                print("pip install python-whois dnspython")
                return
        
        analyzer = EmailHeaderAnalyzer()
        
        # 사용자에게 옵션 제공
        print("\n=== 이메일 헤더 분석 프로그램 ===\n")
        print("1. 이메일 파일 분석")
        print("2. 샘플 이메일 생성 후 분석")
        print("3. 직접 이메일 헤더 입력")
        
        choice = input("\n선택 (1-3): ").strip()
        
        # 이메일 파일 설정
        email_file = None
        raw_email = None
        
        if choice == "1":
            email_file = input("분석할 이메일 파일 경로 (기본값: email.eml): ").strip() or "email.eml"
        elif choice == "2":
            email_file = create_sample_email()
        elif choice == "3":
            print("\n이메일 헤더를 직접 입력하세요. 입력을 완료하면 빈 줄 입력 후 Ctrl+D 또는 Ctrl+Z (Windows):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                raw_email = "\n".join(lines)
        else:
            print("잘못된 선택입니다. 기본값(1)으로 진행합니다.")
            email_file = "email.eml"
        
        # 파일에서 읽기
        if email_file:
            try:
                if not os.path.exists(email_file):
                    print(f"오류: 파일 '{email_file}'이 존재하지 않습니다.")
                    return
                    
                print(f"파일 '{email_file}'을 읽는 중...")
                with open(email_file, "rb") as f:
                    raw_email = f.read()
                print(f"파일 크기: {len(raw_email)} 바이트")
            except Exception as e:
                print(f"파일 읽기 오류: {e}")
                return
        
        # 이메일 분석
        if raw_email:
            result = analyzer.analyze_email(raw_email)
            
            # 결과 출력
            print("\n===== 이메일 분석 결과 =====")
            print(f"최종 판정: {result.get('final_verdict', 'unknown')}")
            
            # 발신자 도메인 정보
            tech_domain = result.get('technical_sender_domain', '확인 불가')
            from_domain = result.get('from_domain', '확인 불가')
            sender_domain = result.get('sender_domain', '확인 불가')
            
            if from_domain and tech_domain and from_domain != tech_domain:
                print(f"발신자 표시 도메인: {from_domain}")
                print(f"실제 발송 서버: {tech_domain}")
                
                if result.get("sender_note"):
                    print(f"참고: {result.get('sender_note')}")
            else:
                print(f"발신자 도메인: {sender_domain}")
            
            # 기관 유형 정보
            if 'organization_type' in result and 'organization_subtype' in result:
                # 대분류
                main_type = result['organization_type']
                main_type_korean = {
                    'public': '공공기관',
                    'financial': '금융기관',
                    'education': '교육기관',
                    'technology': 'IT/기술 기업',
                    'manufacturing': '제조/산업 기업',
                    'service': '서비스 기업',
                    'media': '미디어/엔터테인먼트',
                    'healthcare': '의료/제약',
                    'nonprofit': '비영리기관',
                    'commercial': '일반 기업',
                    'unknown': '미확인'
                }.get(main_type, main_type)
                
                # 소분류
                sub_type = result.get('organization_subtype', 'unknown')
                sub_type_korean = {
                    # 공공기관
                    'government': '정부기관',
                    'military': '군사기관',
                    'public_corporation': '공기업',
                    'local_government': '지방자치단체',
                    
                    # 금융기관
                    'bank': '은행',
                    'insurance': '보험회사',
                    'securities': '증권사',
                    'card': '카드사',
                    
                    # 교육기관
                    'university': '대학교',
                    'school': '초중고등학교',
                    'research': '연구기관',
                    
                    # IT/기술
                    'it_software': 'IT/소프트웨어',
                    'telecom': '통신회사',
                    
                    # 제조/산업
                    'manufacturing': '제조업',
                    'electronics': '전자기업',
                    'automotive': '자동차기업',
                    
                    # 유통/서비스
                    'retail_logistics': '유통/물류',
                    'food_beverage': '식품/음료',
                    'travel_hospitality': '여행/숙박',
                    'recruitment': '채용/인사 서비스',
                    
                    # 기타
                    'media_entertainment': '미디어/엔터테인먼트',
                    'healthcare_pharma': '의료/제약',
                    'ngo_foundation': 'NGO/재단',
                    'religious': '종교기관',
                    'general_business': '일반 기업',
                    'network_provider': '네트워크 제공업체',
                    'unknown': '분류 불가'
                }.get(sub_type, sub_type)
                
                print(f"발신자 기관 유형: {main_type_korean} > {sub_type_korean}")
                
                # From 도메인의 기관 유형이 다를 경우 표시
                if ('from_organization_type' in result) and ('from_organization_subtype' in result):
                    from_main_type = result['from_organization_type']
                    from_sub_type = result['from_organization_subtype']
                    
                    if from_main_type != 'unknown' and (from_main_type != main_type or from_sub_type != sub_type):
                        from_main_type_korean = {
                            'public': '공공기관',
                            'financial': '금융기관',
                            'education': '교육기관',
                            'technology': 'IT/기술 기업',
                            'manufacturing': '제조/산업 기업',
                            'service': '서비스 기업',
                            'media': '미디어/엔터테인먼트',
                            'healthcare': '의료/제약',
                            'nonprofit': '비영리기관',
                            'commercial': '일반 기업',
                            'unknown': '미확인'
                        }.get(from_main_type, from_main_type)
                        
                        from_sub_type_korean = sub_type_korean = {
                            # 공공기관
                            'government': '정부기관',
                            'military': '군사기관',
                            'public_corporation': '공기업',
                            'local_government': '지방자치단체',
                            
                            # 금융기관
                            'bank': '은행',
                            'insurance': '보험회사',
                            'securities': '증권사',
                            'card': '카드사',
                            
                            # 교육기관
                            'university': '대학교',
                            'school': '초중고등학교',
                            'research': '연구기관',
                            
                            # IT/기술
                            'it_software': 'IT/소프트웨어',
                            'telecom': '통신회사',
                            
                            # 제조/산업
                            'manufacturing': '제조업',
                            'electronics': '전자기업',
                            'automotive': '자동차기업',
                            
                            # 유통/서비스
                            'retail_logistics': '유통/물류',
                            'food_beverage': '식품/음료',
                            'travel_hospitality': '여행/숙박',
                            'recruitment': '채용/인사 서비스',
                            
                            # 기타
                            'media_entertainment': '미디어/엔터테인먼트',
                            'healthcare_pharma': '의료/제약',
                            'ngo_foundation': 'NGO/재단',
                            'religious': '종교기관',
                            'general_business': '일반 기업',
                            'network_provider': '네트워크 제공업체',
                            'unknown': '분류 불가'
                        }.get(from_sub_type, from_sub_type)
                        
                        print(f"발신자 표시 기관 유형: {from_main_type_korean} > {from_sub_type_korean}")
                
                # 특별 공지 출력
                if 'notice' in result:
                    print(f"\n[중요] {result['notice']}")
            
            print(f"DNSSEC 상태: {result.get('dnssec_status', 'unknown')}")
            print(f"SPF 체크: {result.get('spf_check', 'unknown')}")
            print(f"DKIM 체크: {result.get('dkim_check', 'unknown')}")
            print(f"DMARC 체크: {result.get('dmarc_check', 'unknown')}")
            
            # 의심 이유가 있을 경우만 표시
            if result.get("reasons"):
                print("\n의심 이유:")
                for reason in result["reasons"]:
                    print(f"  - {reason}")
            
            if "details" in result and "domain_info" in result["details"]:
                print("\n도메인 정보:")
                for key, value in result["details"]["domain_info"].items():
                    print(f"  {key}: {value}")
            
            # IP 리스트 출력
            if analyzer.spf_ip_list:
                print("\nSPF IP 목록:")
                for ip in analyzer.spf_ip_list:
                    print(f"  {ip}")
            
            if analyzer.dig_ip_list:
                print("\nDNS TXT IP 목록:")
                for ip in analyzer.dig_ip_list:
                    print(f"  {ip}")
        else:
            print("오류: 분석할 이메일이 없습니다.")
            
    except Exception as e:
        print(f"프로그램 실행 중 오류 발생: {e}")
        print(traceback.format_exc())

if __name__ == "__main__":
    main()