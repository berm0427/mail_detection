# email_analyzer/body_analyzer.py
import os
import re
import json
import logging
from pathlib import Path

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BodyAnalyzer:
    """이메일 본문 분석기"""
    
    def __init__(self, keywords_dir):
        self.keywords_dir = Path(keywords_dir)
        self.keywords = {}
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
        """텍스트 본문 분석"""
        if not text:
            return {"total_matches": 0, "categories": {}}
        
        # 기관 유형에 맞는 키워드 선택
        keywords_to_use = self.load_organization_specific_keywords(organization_type, organization_subtype)
        
        # 결과 초기화
        result = {
            "total_matches": 0,
            "categories": {}
        }
        
        # 각 카테고리별 키워드 검사
        for category, patterns in keywords_to_use.items():
            logger.info(f"{category} 카테고리 패턴 검사 시작")
            matches = 0
            examples = []
            
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
                result["categories"][category] = {
                    "count": matches,
                    "examples": examples
                }
                result["total_matches"] += matches
        
        return result