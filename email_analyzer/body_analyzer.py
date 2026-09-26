# email_analyzer/body_analyzer.py
import re
import logging

from email_analyzer.url_features import URLFeatureExtractor

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BodyAnalyzer:
    """이메일 본문 분석기"""
    
    def __init__(self):
        self.url_feature_extractor = URLFeatureExtractor()
    
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
        """URL을 모으고 판정 없이 구조 특징을 기록한다."""
        origins = {url: ['body_text'] for url in self.extract_urls(text)}
        for item in additional_urls or []:
            sources = origins.setdefault(item['url'], [])
            if item['source'] not in sources:
                sources.append(item['source'])

        analyzed_urls = []
        for url, sources in origins.items():
            try:
                features = self.url_feature_extractor.extract(url)
            except (TypeError, ValueError):
                features = {'parse_error': True}
            analyzed_urls.append({'url': url, 'sources': sources, 'structural_features': features})

        logger.info("URL 구조 관측 완료 - 총 %d개", len(analyzed_urls))
        return {
            'total_urls': len(analyzed_urls),
            'analyzed_urls': analyzed_urls,
            'analysis_mode': 'structural_observation',
            'scoring_applied': False,
        }

    def analyze_text(self, text, organization_type='unknown', organization_subtype='unknown', additional_urls=None):
        """텍스트 본문 분석 (URL 분석 포함)"""
        if not text:
            return {
                "url_analysis": {
                    'total_urls': 0,
                    'analyzed_urls': [],
                    'analysis_mode': 'structural_observation',
                    'scoring_applied': False
                }
            }
        
        result = {}

        # 2. URL 분석
        url_analysis = self.analyze_urls(text, additional_urls)
        result["url_analysis"] = url_analysis
        
        return result

