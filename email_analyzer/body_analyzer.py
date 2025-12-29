# email_analyzer/body_analyzer.py
import os
import re
import json
import logging
from pathlib import Path

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingURLDetector:
    """피싱 URL 탐지 클래스"""
    
    def __init__(self):
        # 1. IP 주소 직접 사용 (IPv4)
        self.ip_pattern = re.compile(r'https?://(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)')
        
        # 2. 의심스러운 TLD (Top Level Domain) - 신뢰할 수 있는 TLD 제외
        self.suspicious_tld = re.compile(r'\.(tk|ml|ga|cf|gq|pw|top|click|download|stream|link|site|online|cc|xyz|pp\.ua)(?:/|$)', re.IGNORECASE)
        
        # 3. 긴 서브도메인 (4개 이상의 서브도메인) - 기준 완화
        self.long_subdomain = re.compile(r'https?://[^/]*\.([^./]+\.){4,}[^./]+\.[a-z]{2,4}', re.IGNORECASE)
        
        # 4. URL 단축 서비스
        self.url_shortener = re.compile(r'https?://(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link|tiny\.cc|is\.gd|buff\.ly)', re.IGNORECASE)
        
        # 5. 의심스러운 키워드가 포함된 도메인 - 정확한 브랜드 사칭만 탐지
        self.suspicious_keywords = re.compile(r'(secure|login|verify|update|confirm|account)[-.]?(bank|paypal|amazon|apple|google|microsoft|naver|kakao|samsung)[-.]?\w*\.(com|net|org|co\.kr)', re.IGNORECASE)
        
        # 6. 과도한 하이픈 사용 (3개 이상 연속)
        self.excessive_hyphens = re.compile(r'https?://[^/]*-{3,}[^/]*', re.IGNORECASE)
        
        # 7. 도메인에 의심스러운 숫자 패턴 (도메인 부분만, 경로 제외)
        self.numeric_domain = re.compile(r'https?://[^/]*[0-9]{5,}[^/]*/', re.IGNORECASE)  # 5자리 이상 숫자
        
        # 8. 유명 브랜드명 뒤에 추가 문자 - 더 정교한 패턴
        self.brand_impersonation = re.compile(r'(naver|daum|kakao|samsung|lotte|hyundai|lg|sk|kt|payco|toss|kbank|woori|shinhan|hana|nh|keb)[-_][a-z0-9]{3,}\.(com|net|org|co\.kr)', re.IGNORECASE)
        
        # 9. 과도하게 긴 URL (150자 이상으로 완화)
        self.long_url = re.compile(r'^.{150,}$')
        
        # 10. 의심스러운 파라미터 패턴
        self.suspicious_params = re.compile(r'[?&](redirect|url|link|goto|return|continue|next)=https?://', re.IGNORECASE)
        
        # 11. 혼동을 일으키는 문자 (3개 이상 연속)
        self.confusing_chars = re.compile(r'https?://[^/]*[1l0O]{3,}[^/]*', re.IGNORECASE)
        
        # 12. 한글 도메인 피싱 패턴 (도메인 부분만)
        self.hangul_domain = re.compile(r'https?://[^/]*[\u3131-\u318F\uAC00-\uD7A3]+[^/]*/')
        
        # 13. 포트번호가 포함된 의심스러운 URL
        self.suspicious_port = re.compile(r'https?://[^/]+:(?!443|80|8080|8443)(\d+)', re.IGNORECASE)
        
        # 14. 클라우드 스토리지 남용 패턴
        self.cloud_storage_abuse = re.compile(r'https?://(storage\.googleapis\.com|[^.]+\.s3\.[^.]+\.amazonaws\.com|[^.]+\.blob\.core\.windows\.net)/[a-z0-9]{10,}/[a-z0-9]{10,}\.html', re.IGNORECASE)
        
        # 15. 긴 해시/프래그먼트 패턴 (피싱에서 자주 사용)
        self.long_fragment = re.compile(r'#[A-Za-z0-9]{30,}', re.IGNORECASE)
        
        # 16. 랜덤 문자열 패턴 (도메인 경로에서)
        self.random_path = re.compile(r'https?://[^/]+/[a-z0-9]{15,}/[a-z0-9]{15,}\.html', re.IGNORECASE)
        
        # 17. 의심스러운 파일명 패턴
        self.suspicious_filename = re.compile(r'/([a-z0-9]{10,})\.(html|php)(?:[#?]|$)', re.IGNORECASE)
        
        # 18. 신뢰할 수 있는 도메인 패턴 (화이트리스트)
        self.trusted_domains = re.compile(r'https?://[^/]*\.(edu|gov|mil|org|ac\.kr|go\.kr|re\.kr)(?:/|$)', re.IGNORECASE)
        
        # 19. 신뢰할 수 있는 브랜드 도메인
        self.trusted_brands = re.compile(r'https?://(?:www\.)?(hacktheon|github|gitlab|stackoverflow|microsoft|google|apple|amazon|naver|kakao|daum)\.(?:org|com|net|co\.kr)(?:/|$)', re.IGNORECASE)

    def detect_phishing_features(self, url):
        """URL에서 피싱 특징들을 탐지 (개선된 버전)"""
        features = {}
        
        # 먼저 신뢰할 수 있는 도메인인지 확인
        is_trusted_domain = bool(self.trusted_domains.search(url))
        is_trusted_brand = bool(self.trusted_brands.search(url))
        
        if is_trusted_domain or is_trusted_brand:
            # 신뢰할 수 있는 도메인은 완화된 기준 적용
            features['has_ip'] = bool(self.ip_pattern.search(url))
            features['suspicious_tld'] = False  # 신뢰 도메인은 TLD 검사 제외
            features['long_subdomain'] = False  # 신뢰 도메인은 서브도메인 검사 완화
            features['url_shortener'] = bool(self.url_shortener.search(url))
            features['suspicious_keywords'] = False  # 신뢰 도메인은 키워드 검사 제외
            features['excessive_hyphens'] = bool(self.excessive_hyphens.search(url))
            features['numeric_domain'] = False  # 신뢰 도메인은 숫자 검사 제외
            features['brand_impersonation'] = False  # 신뢰 도메인은 브랜드 사칭 제외
            features['long_url'] = bool(self.long_url.search(url))
            features['suspicious_params'] = bool(self.suspicious_params.search(url))
            features['confusing_chars'] = bool(self.confusing_chars.search(url))
            features['hangul_domain'] = False  # 신뢰 도메인은 한글 도메인 검사 제외
            features['suspicious_port'] = bool(self.suspicious_port.search(url))
            features['cloud_storage_abuse'] = bool(self.cloud_storage_abuse.search(url))
            
        else:
            # 일반 도메인은 전체 검사 적용
            features['has_ip'] = bool(self.ip_pattern.search(url))
            features['suspicious_tld'] = bool(self.suspicious_tld.search(url))
            features['long_subdomain'] = bool(self.long_subdomain.search(url))
            features['url_shortener'] = bool(self.url_shortener.search(url))
            features['suspicious_keywords'] = bool(self.suspicious_keywords.search(url))
            features['excessive_hyphens'] = bool(self.excessive_hyphens.search(url))
            features['numeric_domain'] = bool(self.numeric_domain.search(url))
            features['brand_impersonation'] = bool(self.brand_impersonation.search(url))
            features['long_url'] = bool(self.long_url.search(url))
            features['suspicious_params'] = bool(self.suspicious_params.search(url))
            features['confusing_chars'] = bool(self.confusing_chars.search(url))
            features['hangul_domain'] = bool(self.hangul_domain.search(url))
            features['suspicious_port'] = bool(self.suspicious_port.search(url))
            features['cloud_storage_abuse'] = bool(self.cloud_storage_abuse.search(url))
            features['long_fragment'] = bool(self.long_fragment.search(url))
            features['random_path'] = bool(self.random_path.search(url))
            features['suspicious_filename'] = bool(self.suspicious_filename.search(url))
        
        return features

    def calculate_risk_score(self, url):
        """피싱 위험도 점수 계산 (개선된 버전)"""
        features = self.detect_phishing_features(url)
        
        # 신뢰할 수 있는 도메인 확인
        is_trusted_domain = bool(self.trusted_domains.search(url))
        is_trusted_brand = bool(self.trusted_brands.search(url))
        
        if is_trusted_domain or is_trusted_brand:
            # 신뢰할 수 있는 도메인은 가중치 대폭 완화
            weights = {
                'has_ip': 30,           # IP 사용은 여전히 의심
                'suspicious_tld': 0,    # TLD 검사 제외
                'long_subdomain': 0,    # 서브도메인 검사 제외
                'url_shortener': 10,    # 단축 URL 완화
                'suspicious_keywords': 0, # 키워드 검사 제외
                'excessive_hyphens': 5,
                'numeric_domain': 0,    # 숫자 도메인 검사 제외
                'brand_impersonation': 0, # 브랜드 사칭 제외
                'long_url': 5,          # 긴 URL 완화
                'suspicious_params': 15,
                'confusing_chars': 8,
                'hangul_domain': 0,     # 한글 도메인 제외
                'suspicious_port': 12,
                'cloud_storage_abuse': 30      # 클라우드 스토리지 남용
            }
        else:
            # 일반 도메인은 기존 가중치 적용
            weights = {
                'has_ip': 25,
                'suspicious_tld': 15,
                'long_subdomain': 10,
                'url_shortener': 8,
                'suspicious_keywords': 20,
                'excessive_hyphens': 5,
                'numeric_domain': 12,   # 숫자 도메인 가중치 증가
                'brand_impersonation': 25,
                'long_url': 5,
                'suspicious_params': 15,
                'confusing_chars': 10,
                'hangul_domain': 8,
                'suspicious_port': 12,
                'cloud_storage_abuse': 30,      # 클라우드 스토리지 남용
                'long_fragment': 20,            # 긴 해시/프래그먼트
                'random_path': 15,              # 랜덤 경로 패턴
                'suspicious_filename': 12       # 의심스러운 파일명
            }
        
        score = sum(weights[feature] for feature, detected in features.items() if detected)
        return min(score, 100)  # 최대 100점
    
class BodyAnalyzer:
    """이메일 본문 분석기"""
    
    def __init__(self, keywords_dir):
        self.keywords_dir = Path(keywords_dir)
        self.keywords = {}
        self.url_detector = PhishingURLDetector()
        self.load_keywords()
    
    def load_keywords(self):
        """키워드 파일들 로드"""
        if not self.keywords_dir.exists():
            os.makedirs(self.keywords_dir, exist_ok=True)
            logger.warning(f"키워드 디렉토리가 없어 생성됨: {self.keywords_dir}")
            return
        
        # 모든 JSON 파일 로드
        for file_path in self.keywords_dir.glob('*.json'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    keyword_data = json.load(f)
                    category = keyword_data.get('category')
                    keywords = keyword_data.get('blackList_keywords', [])
                    if category and keywords:
                        self.keywords[category] = keywords
                        logger.info(f"키워드 파일 {file_path.name}에서 {len(keywords)}개 패턴 로드")
            except json.JSONDecodeError as e:
                logger.error(f"오류: {file_path.name} 파일 파싱 실패 - {str(e)}")
            except Exception as e:
                logger.error(f"오류: {file_path.name} 파일 로드 중 오류 - {str(e)}")
    
    def extract_urls(self, text):
        """텍스트에서 URL 추출"""
        # URL 패턴 정규식
        url_pattern = re.compile(
            r'https?://[^\s<>"\']+|'  # http/https URL
            r'www\.[^\s<>"\']+|'      # www로 시작하는 URL
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*',  # 일반 도메인 패턴
            re.IGNORECASE
        )
        
        urls = url_pattern.findall(text)
        
        # URL 정제 (끝의 구두점 제거)
        cleaned_urls = []
        for url in urls:
            # 끝의 구두점 제거
            url = re.sub(r'[.,;:!?)\]}>]+$', '', url)
            
            # http/https가 없는 경우 추가
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                else:
                    # 도메인 형태인지 확인
                    if '.' in url and not url.startswith(('mailto:', 'tel:')):
                        url = 'http://' + url
            
            if url and len(url) > 7:  # 최소 길이 확인
                cleaned_urls.append(url)
        
        return list(set(cleaned_urls))  # 중복 제거
    
    def analyze_urls(self, text):
        """텍스트에서 URL을 추출하고 분석"""
        urls = self.extract_urls(text)
        url_analysis = {
            'total_urls': len(urls),
            'suspicious_urls': [],
            'risk_score': 0,
            'features_detected': []
        }
        
        if not urls:
            logger.info("본문에서 URL을 찾지 못했습니다.")
            return url_analysis
        
        logger.info(f"본문에서 {len(urls)}개의 URL 발견")
        
        for url in urls:
            logger.info(f"URL 분석 중: {url}")
            
            # 피싱 특징 탐지
            features = self.url_detector.detect_phishing_features(url)
            risk_score = self.url_detector.calculate_risk_score(url)
            
            if risk_score > 0:
                url_info = {
                    'url': url,
                    'risk_score': risk_score,
                    'features': [feature for feature, detected in features.items() if detected]
                }
                url_analysis['suspicious_urls'].append(url_info)
                url_analysis['features_detected'].extend(url_info['features'])
                
                logger.warning(f"의심스러운 URL 발견: {url} (위험도: {risk_score}/100)")
                logger.warning(f"탐지된 특징: {url_info['features']}")
        
        # 전체 URL 위험도 계산 (가장 높은 점수 사용)
        if url_analysis['suspicious_urls']:
            url_analysis['risk_score'] = max(url['risk_score'] for url in url_analysis['suspicious_urls'])
        
        # 중복 특징 제거
        url_analysis['features_detected'] = list(set(url_analysis['features_detected']))
        
        logger.info(f"URL 분석 완료 - 총 {url_analysis['total_urls']}개, 의심스러운 URL {len(url_analysis['suspicious_urls'])}개, 최대 위험도: {url_analysis['risk_score']}")
        
        return url_analysis

    def load_organization_specific_keywords(self, organization_type, organization_subtype):
        """기관 유형별 맞춤 키워드 로드"""
        # 조직 유형에 따른 키워드 선택
        org_specific_keywords = {}
        
        # 기관 유형 매핑 - 각 유형별로 검사할 키워드 카테고리 정의
        type_category_mapping = {
            "public": {
                "government": ["malicious", "government"],
                "military": ["malicious", "military"],
                "default": ["malicious", "investigation", "government"]
            },
            "financial": {
                "default": ["malicious", "financial"]
            },
            "education": {
                "default": ["malicious", "education"]
            },
            "technology": {
                "default": ["malicious"]
            },
            "user": {
                "default": ["malicious", "financial", "investigation", "government"]
            },
            "default": {
                "default": self.keywords.keys()  # 기본적으로 모든 키워드 사용
            }
        }
        
        # 기관 유형에 따른 카테고리 선택
        categories_to_use = []
        
        # 1단계: 기관 유형 확인
        if organization_type in type_category_mapping:
            # 2단계: 하위 유형 확인
            if organization_subtype in type_category_mapping[organization_type]:
                categories_to_use = type_category_mapping[organization_type][organization_subtype]
            else:
                # 기본 카테고리 사용
                categories_to_use = type_category_mapping[organization_type]["default"]
        else:
            # 알 수 없는 유형은 기본 카테고리 사용
            categories_to_use = type_category_mapping["default"]["default"]
        
        # 선택된 카테고리에 해당하는 키워드 추가
        for category in categories_to_use:
            if category in self.keywords:
                org_specific_keywords[category] = self.keywords[category]
        
        # 키워드가 선택되지 않았으면 모든 키워드 사용
        if not org_specific_keywords:
            for category, patterns in self.keywords.items():
                org_specific_keywords[category] = patterns
        
        logger.info(f"{organization_type}/{organization_subtype} 기관 유형에 대해 {len(org_specific_keywords)} 카테고리 키워드 선택됨")
        return org_specific_keywords
    
    def analyze_text(self, text, organization_type='unknown', organization_subtype='unknown'):
        """텍스트 본문 분석 (URL 분석 포함)"""
        if not text:
            return {
                "total_matches": 0, 
                "categories": {},
                "url_analysis": {
                    'total_urls': 0,
                    'suspicious_urls': [],
                    'risk_score': 0,
                    'features_detected': []
                }
            }
        
        # 기관 유형에 맞는 키워드 선택
        keywords_to_use = self.load_organization_specific_keywords(organization_type, organization_subtype)
        
        # 결과 초기화
        result = {
            "total_matches": 0,
            "categories": {},
            "excluded_categories": {}  # 제외된 카테고리 추가
        }
        
        # 1. 키워드 분석 (카테고리별 예외 처리 추가)
        # 각 카테고리별 키워드 검사
        for category, patterns in keywords_to_use.items():
            logger.info(f"{category} 카테고리 패턴 검사 시작")
            matches = 0
            examples = []
            
            # 카테고리별 예외 처리 확인
            should_exclude_category = self._should_exclude_category(category, organization_type, organization_subtype)
            
            for pattern in patterns:
                logger.info(f"검사할 패턴: {pattern}")
                matches_in_pattern = re.findall(pattern, text)
                
                if matches_in_pattern:
                    num_matches = len(matches_in_pattern)
                    matches += num_matches
                    logger.info(f"패턴 '{pattern}'에서 {num_matches}개 매치 발견")
                    
                    # 예시 수집 (최대 3개)
                    for match in matches_in_pattern[:3]:
                        if isinstance(match, tuple):
                            # 정규식 그룹이 튜플로 반환될 경우
                            match_str = ' '.join(m for m in match if m)
                        else:
                            match_str = match
                        examples.append(match_str)
                else:
                    logger.info(f"패턴 '{pattern}'에서 매치 없음")
            
            if matches > 0:
                if should_exclude_category:
                    # 제외된 카테고리로 분류
                    result["excluded_categories"][category] = {
                        "count": matches,
                        "examples": examples,
                        "reason": f"{organization_type}/{organization_subtype} 기관의 정상 키워드"
                    }
                    logger.info(f"{category} 카테고리 키워드 {matches}개 발견하였지만 {organization_type}/{organization_subtype} 기관이므로 제외")
                else:
                    # 정상 처리
                    result["categories"][category] = {
                        "count": matches,
                        "examples": examples
                    }
                    result["total_matches"] += matches
        
        # 2. URL 분석
        url_analysis = self.analyze_urls(text)
        result["url_analysis"] = url_analysis
        
        return result

    def _should_exclude_category(self, category, organization_type, organization_subtype):
        """카테고리별 예외 처리가 필요한지 확인"""
        
        # IT 서비스에서 malicious 카테고리는 제외 (로그인, 인증 등이 정상)
        if category == 'malicious' and organization_subtype == 'it_software':
            return True
        
        # 금융기관에서 financial 카테고리는 제외
        if category == 'financial' and organization_type == 'financial':
            return True
        
        # 정부기관에서 government 카테고리는 제외
        if category == 'government' and (organization_type == 'public' or organization_subtype == 'government'):
            return True
        
        # 교육기관에서 education 카테고리는 제외
        if category == 'education' and organization_type == 'education':
            return True
        
        # 배송업체에서 delivery 카테고리는 제외 (아직 delivery 서브타입이 없지만 미래 확장성)
        if category == 'delivery' and organization_subtype in ['delivery', 'logistics']:
            return True
        
        # 수사기관에서 investigation 카테고리는 제외
        if category == 'investigation' and organization_subtype in ['police', 'prosecution', 'court']:
            return True
        
        # 군사기관에서 military 카테고리는 제외
        if category == 'military' and organization_subtype == 'military':
            return True
        
        return False