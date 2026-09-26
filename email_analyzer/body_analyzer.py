# email_analyzer/body_analyzer.py
import re
import logging

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
                # 추적·서명 URL도 흔히 길어지므로 길이만으로 위험 점수를 주지 않는다.
                # 특성 자체는 관측·향후 ML 입력을 위해 유지한다.
                'long_url': 0,
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
                # URL 길이는 단독 피싱 증거가 아니다. 다른 구조 신호만 점수화한다.
                'long_url': 0,
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
    
    def __init__(self):
        self.url_detector = PhishingURLDetector()
    
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
    
    def analyze_urls(self, text, additional_urls=None):
        """텍스트에서 URL을 추출하고 분석"""
        origins = {url: ['body_text'] for url in self.extract_urls(text)}
        for item in additional_urls or []:
            sources = origins.setdefault(item['url'], [])
            if item['source'] not in sources:
                sources.append(item['source'])
        urls = list(origins)
        url_analysis = {
            'total_urls': len(urls),
            'analyzed_urls': [],
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
            
            url_analysis['analyzed_urls'].append({'url': url, 'sources': origins[url], 'risk_score': risk_score})
            if risk_score > 0:
                url_info = {
                    'url': url,
                    'sources': origins[url],
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

    def analyze_text(self, text, organization_type='unknown', organization_subtype='unknown', additional_urls=None):
        """텍스트 본문 분석 (URL 분석 포함)"""
        if not text:
            return {
                "url_analysis": {
                    'total_urls': 0,
                    'suspicious_urls': [],
                    'risk_score': 0,
                    'features_detected': []
                }
            }
        
        result = {
            "action_signals": [],
        }
        # Direct urgent payment requests, not isolated institution names.
        for m in re.finditer(r'(?:즉시|지금|긴급히)\s*(?:납부|송금|입금|결제)(?:해\s*주(?:시기|세요)|하(?:세요|십시오)|바랍니다)', text):
            result['action_signals'].append({'kind':'urgent_payment_request','span':list(m.span())})

        # 2. URL 분석
        url_analysis = self.analyze_urls(text, additional_urls)
        result["url_analysis"] = url_analysis
        
        return result

