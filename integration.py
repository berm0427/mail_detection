# email_analyzer/integration.py
import os
from langdetect import detect
import spacy
from typing import Set, Tuple
import nltk
from nltk import ne_chunk, pos_tag, word_tokenize
from nltk.tree import Tree
import logging
import json
import pandas as pd
import uuid
from sentence_transformers import SentenceTransformer
import numpy as np
import traceback
from sklearn.metrics.pairwise import cosine_similarity
import re
from pathlib import Path
from datetime import datetime
import traceback
from email import policy
from email.parser import BytesParser
from email.header import decode_header
import asyncio
import aiohttp
import hashlib
import time
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from collections import Counter
import statistics
import subprocess
import sys
import json
import pickle
import tempfile
from tqdm import tqdm
import zipfile

if sys.platform == 'win32':
    # JAVA_HOME 환경 변수 확인
    java_home = os.environ.get('JAVA_HOME')
    if java_home:
        os.environ['PATH'] = f"{java_home}\\bin;{os.environ['PATH']}"


def run_konlpy_subprocess(text):
    """subprocess로 KoNLPy 실행"""
    try:
        # KoNLPy 실행용 Python 코드
        konlpy_code = f"""
import sys
import json
import re
from konlpy.tag import Okt

text = '''{text[:1000]}'''
try:
    okt = Okt()
    clean_text = re.sub(r'[^\\w\\s가-힣]', ' ', text)
    pos_tags = okt.pos(clean_text)
    
    entities = []
    current_entity = []
    for word, tag in pos_tags:
        if tag in ['Noun', 'ProperNoun', 'Modifier', 'Alpha']:
            current_entity.append(word)
        else:
            if current_entity:
                entity = ''.join(current_entity)
                if len(entity) >= 2 and not entity.isdigit():
                    entities.append(entity)
            current_entity = []
    
    if current_entity:
        entity = ''.join(current_entity)
        if len(entity) >= 2 and not entity.isdigit():
            entities.append(entity)
    
    print(json.dumps({{'success': True, 'entities': entities}}))
except Exception as e:
    print(json.dumps({{'success': False, 'error': str(e)}}))
"""
        
        # subprocess로 Python 실행
        result = subprocess.run(
            [sys.executable, '-c', konlpy_code],
            capture_output=True,
            text=True,
            timeout=100
        )
        
        if result.returncode == 0 and result.stdout:
            output = json.loads(result.stdout.strip())
            if output.get('success'):
                return output.get('entities', [])
        
        return []
        
    except subprocess.TimeoutExpired:
        logger.warning("KoNLPy subprocess 타임아웃")
        return []
    except Exception as e:
        logger.error(f"KoNLPy subprocess 오류: {e}")
        return []    


# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# NLTK 데이터 다운로드 (최초 실행 시 필요)
try:
    nltk.download('punkt', quiet=True)
    nltk.download('punkt_tab', quiet=True)  # 추가
    nltk.download('averaged_perceptron_tagger', quiet=True)
    nltk.download('maxent_ne_chunker', quiet=True)
    nltk.download('maxent_ne_chunker_tab', quiet=True)  # 추가 - 이게 중요!
    nltk.download('words', quiet=True)
    nltk.download('stopwords', quiet=True)  # 선택사항
except:
    pass

# SpaCy 모델 로드 (한국어와 영어 지원)
SPACY_AVAILABLE = False
nlp_ko = None
nlp_en = None

try:
    nlp_ko = spacy.load("ko_core_news_sm")
    logger.info("한국어 SpaCy 모델 로드 성공")
    SPACY_AVAILABLE = True
except:
    # 모델이 없으면 자동 다운로드
    logger.info("한국어 SpaCy 모델 다운로드 중")
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "ko_core_news_sm"])
    logger.info("한국어 SpaCy 모델 다운로드 성공! 로드 중")
    nlp_ko = spacy.load("ko_core_news_sm")
    logger.info("한국어 SpaCy 모델 로드 성공")
    SPACY_AVAILABLE = True

try:
    nlp_ko = spacy.load("ko_core_news_sm")
    logger.info("영어 SpaCy 모델 로드 성공")
    SPACY_AVAILABLE = True
except:
    # 모델이 없으면 자동 다운로드
    logger.info("영어 SpaCy 모델 다운로드 중")
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    logger.info("영어 SpaCy 모델 다운로드 성공! 로드 중")
    nlp_ko = spacy.load("en_core_web_sm")
    logger.info("영어 SpaCy 모델 로드 성공")
    SPACY_AVAILABLE = True


if not SPACY_AVAILABLE:
    logger.warning("SpaCy 모델을 사용할 수 없습니다.")

# AI 라이브러리 임포트
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("anthropic 라이브러리를 찾을 수 없습니다.")

# config 임포트
try:
    from config import (
        ANTHROPIC_API_KEY, 
        AI_ENABLED, 
        AI_MODEL
    )
except ImportError:
    logger.warning("config.py 파일을 찾을 수 없습니다.")
    AI_ENABLED = False
    ANTHROPIC_API_KEY = None



# 프로젝트 루트 경로 추가
import sys
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# 헤더 분석기 가져오기
try:
    from mail_header.mail_header_detection_v4 import EmailHeaderAnalyzer
    logger.info("헤더 분석기 임포트 성공")
except ImportError as e:
    logger.error(f"헤더 분석기 임포트 실패: {e}")
    raise

# 본문 분석기 가져오기
from email_analyzer.body_analyzer import BodyAnalyzer

class PhishingKnowledgeBase:
    """학습된 피싱 패턴 지식 베이스"""
    
    def __init__(self):
        self.patterns = {
            'urls': {},
            'domains': {},
            'keywords': {},
            'subject_patterns': {},
            'sender_patterns': {},
            'korean_patterns': {},
            'html_patterns': {},
            'form_patterns': {}
        }
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.case_embeddings = None
        self.case_texts = []
        self.case_labels = []
        self.few_shot_examples = []
        self.statistics = {}
        self.trained_date = None

    def add_to_vector_db(self, texts, labels):
        """이메일 텍스트를 벡터로 변환하여 저장"""
        embeddings = self.embedding_model.encode(texts, convert_to_numpy=True)
        if self.case_embeddings is None:
            self.case_embeddings = embeddings
        else:
            self.case_embeddings = np.vstack([self.case_embeddings, embeddings])
        self.case_texts.extend(texts)
        self.case_labels.extend(labels)
    
    def retrieve_similar_threats(self, email_text, top_k=3):
        """지식 베이스에서 유사한 피싱 사례를 검색 (RAG)"""
        if not self.knowledge_base or self.knowledge_base.case_embeddings is None:
            logger.warning("벡터 DB가 비어 있어 RAG 검색을 수행할 수 없습니다.")
            return []

        try:
            # 1. 입력 텍스트 임베딩 생성
            query_embedding = self.knowledge_base.embedding_model.encode([email_text])
            
            # 2. 코사인 유사도 계산 및 1차원 배열로 변환
            similarities = cosine_similarity(
                query_embedding, 
                self.knowledge_base.case_embeddings
            ).flatten()
            
            # 3. 유사도가 높은 상위 k개 인덱스 추출
            top_indices = np.argsort(similarities)[-top_k:][::-1]
            
            results = []
            for idx in top_indices:
                # CRITICAL FIX: numpy.int64를 Python int로 변환
                idx = int(idx)
                
                results.append({
                    'text': self.knowledge_base.case_texts[idx],
                    'label': self.knowledge_base.case_labels[idx],
                    'score': float(similarities[idx])  # numpy.float64도 Python float로 변환
                })
            
            logger.info(f"RAG 검색 완료: {len(results)}개의 유사 사례 발견")
            return results

        except Exception as e:
            logger.error(f"RAG 검색 중 오류 발생: {e}")
            logger.error(f"상세 정보: query_embedding shape: {query_embedding.shape}, "
                        f"case_embeddings shape: {self.knowledge_base.case_embeddings.shape}")
            return []
    
    def download_and_learn_korean_dataset(self):
        """한국 보이스피싱 데이터셋 다운로드 및 학습"""
        import requests
        import zipfile
        import shutil
        
        logger.info("한국 보이스피싱 데이터셋 다운로드 중...")
        
        # GitHub에서 데이터 다운로드
        repo_url = "https://github.com/Voice-Phishing-Detection-App/ML/archive/refs/heads/main.zip"
        
        try:
            # 다운로드
            response = requests.get(repo_url, stream=True)
            with open("korean_phishing.zip", 'wb') as f:
                total_size = int(response.headers.get('content-length', 0))
                with tqdm(total=total_size, unit='B', unit_scale=True) as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        pbar.update(len(chunk))
            
            # 압축 해제
            logger.info("압축 해제 중...")
            with zipfile.ZipFile("korean_phishing.zip", 'r') as zip_ref:
                zip_ref.extractall("korean_dataset_temp")
            
            # 데이터 파일 찾기 및 처리
            korean_phishing = []
            korean_normal = []
            
            # ML-main 폴더 내의 CSV/JSON 파일 탐색
            import glob
            data_files = glob.glob("korean_dataset_temp/**/*.csv", recursive=True)
            data_files.extend(glob.glob("korean_dataset_temp/**/*.json", recursive=True))
            
            for file_path in data_files:
                try:
                    if file_path.endswith('.csv'):
                        df = pd.read_csv(file_path, encoding='utf-8')
                    elif file_path.endswith('.json'):
                        df = pd.read_json(file_path, encoding='utf-8')
                    else:
                        continue
                    
                    logger.info(f"파일 처리 중: {file_path}")
                    logger.debug(f"컬럼: {df.columns.tolist()}")
                    
                    # 컬럼명 표준화
                    df.columns = df.columns.str.lower().str.strip()
                    
                    # 라벨과 텍스트 컬럼 찾기
                    label_col = None
                    text_col = None
                    
                    # 가능한 라벨 컬럼명
                    for col in ['label', 'is_phishing', 'phishing', 'spam', 'class', 'type', '라벨', '분류']:
                        if col in df.columns:
                            label_col = col
                            break
                    
                    # 가능한 텍스트 컬럼명
                    for col in ['text', 'message', 'content', 'body', 'transcript', '내용', '메시지', '텍스트']:
                        if col in df.columns:
                            text_col = col
                            break
                    
                    if label_col and text_col:
                        # 피싱/정상 분류
                        for idx, row in df.iterrows():
                            text = str(row[text_col])
                            label = row[label_col]
                            
                            # 라벨 판단 (1, True, 'phishing', '피싱' 등)
                            if label in [1, '1', True, 'true', 'phishing', '피싱', 'spam', '스팸']:
                                korean_phishing.append(text)
                            else:
                                korean_normal.append(text)
                        
                        logger.info(f"{file_path}: 피싱 {len(korean_phishing)}개, 정상 {len(korean_normal)}개")
                    
                except Exception as e:
                    logger.warning(f"파일 처리 실패 {file_path}: {e}")
                    continue
            
            # 정리
            shutil.rmtree("korean_dataset_temp", ignore_errors=True)
            os.remove("korean_phishing.zip")
            
            logger.info(f"한국 데이터셋: 피싱 {len(korean_phishing)}개, 정상 {len(korean_normal)}개")
            
            return korean_phishing, korean_normal
            
        except Exception as e:
            logger.error(f"한국 데이터셋 다운로드 실패: {e}")
            return [], []

    def learn_combined_datasets(self):
        """Zenodo와 한국 데이터셋 통합 학습"""
        all_phishing = []
        all_normal = []
        
        # 1. Zenodo 데이터셋 로드
        logger.info("Zenodo 데이터셋 로드 중...")
        zenodo_phishing, zenodo_normal = self.load_zenodo_files()
        all_phishing.extend(zenodo_phishing)
        all_normal.extend(zenodo_normal)
        
        # 2. 한국 데이터셋 로드
        logger.info("한국 데이터셋 로드 중...")
        korean_phishing, korean_normal = self.download_and_learn_korean_dataset()
        all_phishing.extend(korean_phishing)
        all_normal.extend(korean_normal)
        
        # 3. 통합 학습
        logger.info(f"통합 학습 시작: 피싱 {len(all_phishing)}개, 정상 {len(all_normal)}개")
        self.learn_patterns(all_phishing, all_normal)
        
        # 4. 통계 업데이트
        self.statistics = {
            'total_samples': len(all_phishing) + len(all_normal),
            'phishing_samples': len(all_phishing),
            'normal_samples': len(all_normal),
            'zenodo_samples': len(zenodo_phishing) + len(zenodo_normal),
            'korean_samples': len(korean_phishing) + len(korean_normal),
            'phishing_ratio': len(all_phishing) / (len(all_phishing) + len(all_normal))
        }
        
        self.trained_date = datetime.now().isoformat()
        logger.info(f"통합 학습 완료!")
    
    def download_and_learn_zenodo(self):
        """Zenodo 데이터셋 다운로드 및 학습"""
        zenodo_url = "https://zenodo.org/api/records/8339691/files-archive"
        
        logger.info("Zenodo 11개 통합 데이터셋 다운로드 중...")
        
        # 다운로드
        response = requests.get(zenodo_url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        
        with open("zenodo_phishing.zip", 'wb') as f:
            with tqdm(total=total_size, unit='B', unit_scale=True) as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    pbar.update(len(chunk))
        
        # 압축 해제
        logger.info("압축 해제 중...")
        with zipfile.ZipFile("zenodo_phishing.zip", 'r') as zip_ref:
            zip_ref.extractall("zenodo_datasets")
        
        # 데이터 로드 및 학습
        self.learn_from_zenodo_files()
        
        logger.info("Zenodo 학습 완료")
    
    def learn_from_zenodo_files(self):
        """Zenodo 파일들에서 패턴 학습"""
        import csv
        
        all_phishing = []
        all_normal = []
        
        dataset_files = [
            "CEAS_08.csv", "Enron.csv", "Ling.csv",
            "Nazario.csv", "Nazario_5.csv", "Nigerian_5.csv", 
            "SpamAssassin.csv", "Nigerian_Fraud.csv", 
            "TREC_05.csv", "TREC_06.csv", "TREC_07.csv"
        ]
        
        for file in dataset_files:
            file_path = f"zenodo_datasets/{file}"
            if os.path.exists(file_path):
                try:
                    # 먼저 Python 엔진으로 시도
                    try:
                        df = pd.read_csv(file_path, 
                                       engine='python',  # Python 엔진 사용
                                       encoding='utf-8', 
                                       on_bad_lines='skip',
                                       quoting=csv.QUOTE_MINIMAL)  # 따옴표 처리
                    except:
                        # 실패시 다른 인코딩과 설정으로 재시도
                        try:
                            df = pd.read_csv(file_path, 
                                           engine='python',
                                           encoding='latin-1',  # 다른 인코딩
                                           on_bad_lines='skip',
                                           sep=',',
                                           quotechar='"',
                                           escapechar='\\')
                        except:
                            # 그래도 실패하면 더 관대한 설정으로
                            df = pd.read_csv(file_path,
                                           engine='python',
                                           encoding='utf-8',
                                           on_bad_lines='skip',
                                           error_bad_lines=False,  # 구버전 pandas 호환
                                           warn_bad_lines=False,
                                           low_memory=False)  # 메모리 제한 해제
                    
                    # 데이터프레임이 비어있는지 확인
                    if df.empty:
                        logger.warning(f"파일 {file}이 비어있습니다.")
                        continue
                    
                    # 컬럼명 표준화 (대소문자 구분 없이)
                    df.columns = df.columns.str.lower().str.strip()
                    
                    # 라벨과 텍스트 컬럼 찾기
                    label_col = None
                    text_col = None
                    
                    # 라벨 컬럼 찾기
                    for col in ['label', 'spam', 'class', 'is_spam', 'phishing']:
                        if col in df.columns:
                            label_col = col
                            break
                    
                    # 텍스트 컬럼 찾기
                    for col in ['text', 'body', 'content', 'message', 'email', 'mail']:
                        if col in df.columns:
                            text_col = col
                            break
                    
                    if label_col and text_col:
                        # NaN 값 제거
                        df = df.dropna(subset=[label_col, text_col])
                        
                        # 라벨 값 표준화 (1 = 피싱/스팸, 0 = 정상)
                        # 문자열 라벨 처리
                        if df[label_col].dtype == 'object':
                            df[label_col] = df[label_col].str.lower()
                            phishing_labels = ['spam', 'phishing', '1', 'true', 'yes']
                            df[label_col] = df[label_col].apply(lambda x: 1 if str(x).lower() in phishing_labels else 0)
                        
                        # 데이터 추출
                        phishing = df[df[label_col] == 1][text_col].tolist()
                        normal = df[df[label_col] == 0][text_col].tolist()
                        
                        # 빈 문자열 제거
                        phishing = [str(x) for x in phishing if x and str(x).strip()]
                        normal = [str(x) for x in normal if x and str(x).strip()]
                        
                        all_phishing.extend(phishing)
                        all_normal.extend(normal)
                        
                        logger.info(f"파일 {file} 로드 성공: 피싱 {len(phishing)}개, 정상 {len(normal)}개")
                    else:
                        logger.warning(f"파일 {file}에서 필요한 컬럼을 찾을 수 없습니다. 컬럼: {df.columns.tolist()}")
                        
                except Exception as e:
                    logger.error(f"파일 {file} 로드 실패: {e}")
                    # 파일 정보 출력하여 디버깅
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            first_line = f.readline()
                            logger.debug(f"파일 {file} 첫 줄: {first_line[:100]}")
                    except:
                        pass
        
        # 데이터가 있는지 확인
        if not all_phishing and not all_normal:
            logger.error("학습할 데이터가 없습니다.")
            return False
        
        # 패턴 학습
        self.learn_patterns(all_phishing, all_normal)
        
        # 통계 저장
        total = len(all_phishing) + len(all_normal)
        self.statistics = {
            'total_samples': total,
            'phishing_samples': len(all_phishing),
            'normal_samples': len(all_normal),
            'phishing_ratio': len(all_phishing) / total if total > 0 else 0
        }
        
        self.trained_date = datetime.now().isoformat()
        logger.info(f"학습 완료: 총 {total}개 샘플 (피싱: {len(all_phishing)}, 정상: {len(all_normal)})")
        
        return True
    
    def learn_patterns(self, phishing_texts: List[str], normal_texts: List[str]):
        """피싱과 정상 이메일에서 패턴 학습"""
        
        # URL 패턴 학습
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
        for text in phishing_texts[:2000]:  # 샘플링
            urls = re.findall(url_pattern, str(text), re.IGNORECASE)
            for url in urls:
                domain = re.search(r'https?://([^/]+)', url)
                if domain:
                    domain_name = domain.group(1)
                    self.patterns['domains'][domain_name] = \
                        self.patterns['domains'].get(domain_name, 0) + 1
        
        # 키워드 빈도 차이 학습
        phishing_words = []
        normal_words = []
        
        for text in phishing_texts[:2000]:
            words = re.findall(r'\b[a-zA-Z]{3,}\b', str(text).lower())
            phishing_words.extend(words)
        
        for text in normal_texts[:2000]:
            words = re.findall(r'\b[a-zA-Z]{3,}\b', str(text).lower())
            normal_words.extend(words)
        
        phishing_counter = Counter(phishing_words)
        normal_counter = Counter(normal_words)
        
        # 피싱 특화 키워드 추출
        for word, count in phishing_counter.most_common(200):
            phishing_freq = count / max(len(phishing_texts), 1)
            normal_freq = normal_counter.get(word, 0) / max(len(normal_texts), 1)
            
            if phishing_freq > normal_freq * 2:
                self.patterns['keywords'][word] = {
                    'phishing_freq': phishing_freq,
                    'normal_freq': normal_freq,
                    'ratio': phishing_freq / (normal_freq + 0.001)
                }
        
        # HTML 패턴 학습
        self.learn_html_patterns(phishing_texts[:500])
        
        # 한국어 패턴 추가
        self.add_korean_patterns()
        
        # Few-shot 예시 생성
        self.create_few_shot_examples(phishing_texts[:5], normal_texts[:5])
        
        all_texts = phishing_texts + normal_texts
        all_labels = ['phishing'] * len(phishing_texts) + ['legitimate'] * len(normal_texts)
        self.add_to_vector_db(all_texts, all_labels)
        
    def learn_html_patterns(self, phishing_texts: List[str]):
        """HTML 패턴 학습"""
        form_count = 0
        input_types = Counter()
        
        for text in phishing_texts:
            if '<form' in str(text).lower():
                form_count += 1
            
            # 입력 필드 타입 추출
            input_matches = re.findall(r'<input[^>]*type=["\']([^"\']+)', str(text), re.IGNORECASE)
            input_types.update(input_matches)
        
        self.patterns['html_patterns'] = {
            'form_ratio': form_count / max(len(phishing_texts), 1),
            'common_input_types': dict(input_types.most_common(10))
        }
    
    def add_korean_patterns(self):
        """한국어 피싱 패턴 추가"""
        self.patterns['korean_patterns'] = {
            'urgent_keywords': ['긴급', '즉시', '24시간', '만료', '정지', '차단', '제한'],
            'credential_keywords': ['비밀번호', '인증', '본인확인', '로그인', '계정', '보안'],
            'financial_keywords': ['송금', '이체', '입금', '출금', '잔액', '결제', '환불'],
            'threat_keywords': ['법적조치', '고발', '신고', '처벌', '제재'],
            'suspicious_domains': ['.tk', '.ml', '.ga', '.cf', '-verify', '-secure', 'bit.ly']
        }
    
    def create_few_shot_examples(self, phishing_samples: List[str], normal_samples: List[str]):
        """Few-shot 예시 생성"""
        for text in phishing_samples:
            self.few_shot_examples.append({
                'text': str(text)[:500],
                'label': 'phishing',
                'indicators': self.extract_indicators(str(text))
            })
        
        for text in normal_samples:
            self.few_shot_examples.append({
                'text': str(text)[:500],
                'label': 'legitimate',
                'indicators': []
            })
    
    def extract_indicators(self, text: str) -> List[str]:
        """텍스트에서 피싱 지표 추출"""
        indicators = []
        
        # 의심스러운 TLD
        if re.search(r'\.(tk|ml|ga|cf)', text, re.IGNORECASE):
            indicators.append("suspicious_tld")
        
        # URL 단축기
        if any(shortener in text.lower() for shortener in ['bit.ly', 'tinyurl', 'goo.gl']):
            indicators.append("url_shortener")
        
        # 긴급성
        if any(word in text.lower() for word in ['urgent', 'immediate', 'expire', '긴급', '즉시']):
            indicators.append("urgency")
        
        # 자격증명 요청
        if re.search(r'(password|verify|confirm|비밀번호|인증)', text, re.IGNORECASE):
            indicators.append("credential_request")
        
        return indicators
    
    def save(self, filepath: str = "phishing_knowledge_base.pkl"):
        """지식 베이스 저장"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'patterns': self.patterns,
                'few_shot_examples': self.few_shot_examples,
                'statistics': self.statistics,
                'trained_date': self.trained_date
            }, f)
        logger.info(f"지식 베이스 저장: {filepath}")
    
    def load(self, filepath: str = "phishing_knowledge_base.pkl") -> bool:
        """지식 베이스 로드"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.patterns = data['patterns']
                self.few_shot_examples = data['few_shot_examples']
                self.statistics = data['statistics']
                self.trained_date = data.get('trained_date')
            logger.info(f"지식 베이스 로드 완료: {filepath}")
            return True
        return False


class IntegratedAnalyzer:
    """통합 이메일 분석기"""
        
    def __init__(self, keywords_dir, result_dir=None, attachments_dir=None):
        self.header_analyzer = EmailHeaderAnalyzer()
        self.body_analyzer = BodyAnalyzer(keywords_dir)
        self.user_email_domains = self.header_analyzer.user_email_domains
        self.result_dir = Path(result_dir) if result_dir else Path("analysis_result")
        self.attachments_dir = Path(attachments_dir) if attachments_dir else self.result_dir / "attachments"
        
        # 브랜드 캐시 초기화
        self.brand_cache = {}
        self.official_sites_cache = {}
        
        # NLP 모델 초기화
        self.setup_nlp_models()

        
        # 결과 저장 디렉토리 생성
        os.makedirs(self.result_dir, exist_ok=True)
        os.makedirs(self.attachments_dir, exist_ok=True)
        
        # URL 캐시
        self.url_cache = {}
        
        # 학습된 지식 베이스 로드
        self.knowledge_base = self.initialize_knowledge_base()
        
        # AI 클라이언트 초기화
        self.setup_ai_clients()
    
    def retrieve_similar_threats(self, email_text, top_k=3):
        """지식 베이스에서 유사한 피싱 사례를 검색 (RAG)"""
        if not self.knowledge_base or self.knowledge_base.case_embeddings is None:
            logger.warning("벡터 DB가 비어 있어 RAG 검색을 수행할 수 없습니다.")
            return []

        try:
            # 1. 입력 텍스트 임베딩 생성
            query_embedding = self.knowledge_base.embedding_model.encode([email_text])
            
            # 2. 코사인 유사도 계산
            # 수정: .flatten() 추가하여 2D -> 1D 변환
            similarities = cosine_similarity(
                query_embedding, 
                self.knowledge_base.case_embeddings
            ).flatten()
            
            # 3. 유사도가 높은 상위 k개 인덱스 추출
            top_indices = np.argsort(similarities)[-top_k:][::-1]
            
            results = []
            for idx in top_indices:
                # numpy.int64를 Python int로 변환
                idx = int(idx)
                
                results.append({
                    'text': self.knowledge_base.case_texts[idx],
                    'label': self.knowledge_base.case_labels[idx],
                    'score': float(similarities[idx])
                })
            
            logger.info(f"RAG 검색 완료: {len(results)}개의 유사 사례 발견")
            return results

        except Exception as e:
            logger.error(f"RAG 검색 중 오류 발생: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []

    
    def initialize_knowledge_base(self) -> PhishingKnowledgeBase:
        kb = PhishingKnowledgeBase()
        kb_path = Path("phishing_knowledge_base.pkl")

        if kb_path.exists():
            kb.load(str(kb_path))
            # [수정] 데이터는 있는데 벡터가 없는 경우를 대비해 임베딩 강제 생성
            if kb.few_shot_examples and kb.case_embeddings is None:
                logger.info("기존 데이터의 벡터 임베딩이 없어 재생성을 시작합니다...")
                # few_shot_examples에서 텍스트와 라벨 추출
                texts = [ex['text'] for ex in kb.few_shot_examples]
                labels = [ex['label'] for ex in kb.few_shot_examples]
                kb.add_to_vector_db(texts, labels) # 70번 메서드 호출
                kb.save(str(kb_path)) # 벡터가 포함된 상태로 다시 저장
        else:
            logger.info("새 지식 베이스 학습 및 벡터화 시작...")
            kb.download_and_learn_zenodo()
            # 학습 직후 벡터 DB 구축 필수
            texts = [ex['text'] for ex in kb.few_shot_examples]
            labels = [ex['label'] for ex in kb.few_shot_examples]
            kb.add_to_vector_db(texts, labels)
            kb.save(str(kb_path))

        return kb
       
    def create_ai_prompt(self, email_data: Dict, comparison_data: Dict) -> str:
        """파밍 사이트 탐지 전용 AI 프롬프트 생성 - 학습 정보 통합"""
        
        # 기존 코드 유지
        header_features = comparison_data.get('header_html_samples', {})
        body_features = comparison_data.get('body_html_samples', {})
        official_features = comparison_data.get('official_sites_html', {})
        
        brand_info = email_data.get('initial_analysis', {}).get('brand_analysis', {})
        brands = brand_info.get('brands', [])
        email_body = email_data.get('body', '')
        
        
        # 1. RAG 검색 수행 (위에서 추가한 메서드 호출)
        # ★ 에러 처리 강화 ★
        similar_cases = []
        try:
            similar_cases = self.retrieve_similar_threats(email_body)
        except Exception as e:
            logger.error(f"RAG 검색 실패, 계속 진행: {e}")
    
        # 2. 검색된 사례를 텍스트로 구성
        reference_cases = ""
        if similar_cases:
            reference_cases = "\n".join([
                f"- 사례(결과:{c['label']}, 유사도:{c['score']:.2f}): {c['text'][:200]}..."
                for c in similar_cases
            ])
        else:
            reference_cases = "참조할 수 있는 유사 사례가 없습니다."
            
        
        brand_contexts = {}
        for brand in brands:
            pattern = rf'.{{0,50}}{re.escape(brand)}.{{0,50}}'
            matches = re.findall(pattern, email_body, re.IGNORECASE)
            if matches:
                brand_contexts[brand] = matches[0].strip()
        
        # 첨부파일 정보 포맷팅
        attachments_list = email_data.get('attachments', [])
        logger.info(f"프롬프트 생성 시 첨부파일 정보: {attachments_list}")
        if not attachments_list:
            attachments_text = "첨부파일: 없음"
        else:
            attachments_text = f"첨부파일 개수: {len(attachments_list)}개\n"
            for idx, attach in enumerate(attachments_list, 1):
                attachments_text += f"\n  [{idx}] {attach.get('filename', 'Unknown')}\n"
                attachments_text += f"      크기: {attach.get('size', 0):,} bytes\n"
                attachments_text += f"      저장 경로: {attach.get('path', 'N/A')}\n"
            
        
        # 학습된 패턴 정보 추가
        learned_patterns = ""
        if self.knowledge_base:
            # 위험 키워드
            dangerous_keywords = [k for k, v in self.knowledge_base.patterns['keywords'].items() 
                                if v['ratio'] > 5][:30]
            
            # 의심 도메인
            suspicious_domains = [d for d, c in self.knowledge_base.patterns['domains'].items() 
                                if c > 10][:20]
            
            # HTML 패턴
            html_patterns = self.knowledge_base.patterns.get('html_patterns', {})
            
            learned_patterns = f"""
        [학습된 피싱 패턴 - {self.knowledge_base.statistics.get('total_samples', 0)}개 샘플]
        위험 키워드 (상위 30): {', '.join(dangerous_keywords)}
        의심 도메인 (빈도 10+): {', '.join(suspicious_domains)}
        피싱 이메일 폼 비율: {html_patterns.get('form_ratio', 0):.2%}
        주요 입력 타입: {html_patterns.get('common_input_types', {})}
        """
            
            # 한국어 패턴
            if 'korean_patterns' in self.knowledge_base.patterns:
                kp = self.knowledge_base.patterns['korean_patterns']
                learned_patterns += f"""
        한국어 긴급 키워드: {', '.join(kp['urgent_keywords'])}
        한국어 인증 키워드: {', '.join(kp['credential_keywords'])}
        한국어 금융 키워드: {', '.join(kp['financial_keywords'])}
        """
        
        # Few-shot 예시 추가
        few_shot_text = ""
        if self.knowledge_base and self.knowledge_base.few_shot_examples:
            few_shot_text = "\n        [학습된 예시]\n"
            for example in self.knowledge_base.few_shot_examples[:3]:
                few_shot_text += f"""
        예시 ({example['label']}):
        텍스트: {example['text'][:200]}...
        지표: {', '.join(example.get('indicators', []))}
        """
        
        # 기존 프롬프트에 학습 정보 통합
        return f"""
        이메일 내 URL이 정상 사이트를 모방한 파밍(Phishing) 사이트인지 정밀 분석하세요.
        
        당신은 {self.knowledge_base.statistics.get('total_samples', 0) if self.knowledge_base else 0}개의 
        실제 피싱 이메일로 학습된 AI 보안 전문가입니다.
        
        [유사 위협 사례]
        {reference_cases}
        {learned_patterns}
        {few_shot_text}

        [이메일 기본 정보]
        제목: {email_data.get('subject', '')}
        발신자: {email_data.get('from', '')}
        본문: {email_data.get('body', '')[:500]}
        
        [브랜드 및 문맥 정보]
        추출된 브랜드/키워드: {brands}
        
        각 브랜드가 사용된 문맥:
        {json.dumps(brand_contexts, ensure_ascii=False, indent=2)}
        
        [검색된 공식 사이트]
        {json.dumps(brand_info.get('official_sites', {}), ensure_ascii=False, indent=2)}
        
        [URL 분석]
        헤더에서 추출된 원본 URL: {comparison_data.get('original_header_urls', [])}
        본문에서 추출된 원본 URL: {comparison_data.get('original_body_urls', [])}
        
        HTML 수집 성공한 헤더 URL: {comparison_data.get('header_urls', [])}
        HTML 수집 성공한 본문 URL: {comparison_data.get('body_urls', [])}
        
        [HTML 내용 비교]
        헤더 도메인 HTML 특징:
        {json.dumps(comparison_data.get('header_html_samples', {}), ensure_ascii=False, indent=2)[:1000]}
        
        본문 URL HTML 특징:
        {json.dumps(comparison_data.get('body_html_samples', {}), ensure_ascii=False, indent=2)[:1000]}
        
        [공식 사이트 HTML 특징]
        {json.dumps(comparison_data.get('official_sites_html', {}), ensure_ascii=False, indent=2)[:1000]}
        
        [정상 사이트 추정 HTML 특징 (헤더 기반)]
        도메인 참조: {[f.get('domain_references', []) for f in header_features.values()]}
        폼 구조: {[f.get('forms', []) for f in header_features.values()]}
        외부 리소스: {[f.get('external_resources', []) for f in header_features.values()]}
        브랜드 키워드: {[f.get('brand_keywords', []) for f in header_features.values()]}
        
        [공식 사이트 HTML 특징 (웹 검색 기반)]
        도메인 참조: {[f.get('domain_references', []) for f in official_features.values()]}
        폼 구조: {[f.get('forms', []) for f in official_features.values()]}
        외부 리소스: {[f.get('external_resources', []) for f in official_features.values()]}
        브랜드 키워드: {[f.get('brand_keywords', []) for f in official_features.values()]}
        텍스트 샘플: {[f.get('text_sample', '')[:100] for f in official_features.values()]}
        구조 정보: {[f.get('structure', '') for f in official_features.values()]}

        [의심 사이트 HTML 특징 (본문 URL)]
        도메인 참조: {[f.get('domain_references', []) for f in body_features.values()]}
        폼 액션 URL: {[f.get('form_actions', []) for f in body_features.values()]}
        로그인 지표: {[f.get('login_indicators', []) for f in body_features.values()]}
        입력 필드 타입: {[f.get('input_types', []) for f in body_features.values()]}
        숨겨진 입력: {[f.get('hidden_inputs', []) for f in body_features.values()]}
        의심스러운 스크립트: {[f.get('suspicious_scripts', []) for f in body_features.values()]}
        iframe 소스: {[f.get('iframe_sources', []) for f in body_features.values()]}
        메타 리다이렉트: {[f.get('meta_redirects', []) for f in body_features.values()]}
        SSL 혼용 콘텐츠: {[f.get('ssl_mixed_content', []) for f in body_features.values()]}
        의심스러운 패턴: {[f.get('suspicious_patterns', []) for f in body_features.values()]}
        버튼 텍스트: {[f.get('button_texts', []) for f in body_features.values()]}
        
        [첨부파일 정보]
        {attachments_text}

        [파밍 사이트 탐지 기준]
        다음 관점에서 종합적으로 분석하세요:
        
        1. 학습된 패턴과 비교
           - 유사 위협 사례(reference_cases)
           - 위험 키워드 매칭 수
           - 의심 도메인 포함 여부
           - HTML 구조 유사성
        
        2. 발신 도메인만으로 악성/정상, 신뢰/의심, 스팸/피싱 여부를 절대 단정하지 마세요.
           - 공식/비공식(@gmail.com, @kakao.com 등) 도메인이 어떻든
           - 메일 본문과 HTML, 실제 코드 및 화면 흐름이 핵심 판단 기준임을 명확히 인식하세요.
           
        3. 메일 본문 내용과 전체 맥락을 종합 평가하세요.
           - 안내, 공지, 정보 전달 등 정상적 목적/행동만 있다면 이를 '정상' 사유로 적극 반영하세요.
           - 단, 정상인 척 위장 가능성도 항상 열린 시각으로 평가하세요.
           - 여러 브랜드가 추출되었을지라도, 실제 피싱 대상은 하나일 가능성이 높습니다.
             문맥을 고려하여 가장 관련성 높은 브랜드를 중심으로 분석하세요.

        4. **도메인 스푸핑 분석**
           - 정상 도메인과 유사한 가짜 도메인 사용 여부
           - 타이포스쿼팅 (철자 유사 도메인) 여부
           - 서브도메인을 이용한 위장 여부
           
        5. 본문 URL의 HTML 코드/웹페이지를 최우선으로 상세 분석하세요.
           - 정상 사이트는 문맥상 관련성을 파악하여 HTML 코드 후보군 중 가장 적합한걸 고르시오
           - 입력 폼, 개인정보, 비밀번호, 로그인 요구, 과도한 클릭 유도, 숨겨진 리다이렉션, 이상한 자바스크립트가 있는지를 실제 코드 분석 결과로 판단하세요.
           - 입력폼, 개인정보 요구가 전혀 없는 순수 안내/공지라면 "정상정보 안내 메일"로 명확하게 결론 내려주세요.
           - "없음"이면 없다를 분명히, 있으면 "어떤 정보/행동을 요구하는지" 구체적이고 객관적으로 명시.
           
        6. **공식 사이트와 의심 사이트 비교**
           - 정상 사이트는 문맥상 관련성을 파악하여 HTML 코드 후보군 중 가장 적합한 것을 선택
           - 예시:
             * 경찰청+과태료 = efine.go.kr (과태료 납부 사이트)
             * 우체국+택배/패키지 = epost.go.kr (택배 조회/배송)
             * 국세청+세금 = hometax.go.kr (세금 납부)
             * 은행+대출 = 해당 은행 대출 페이지
                   
        7. **시각적 모방 정도**
           - 브랜드 키워드 도용 여부
           - CSS 클래스명의 유사성
           - 버튼 텍스트 및 UI 요소 모방 정도

        8. **악성 데이터 수집 의도**
           - 개인정보 입력 폼이 있다면 그 목적지
           - 민감한 정보(카드번호, 주민번호 등) 수집 시도

        9. **기술적 위험 요소**
           - 의심스러운 JavaScript 실행 여부
           - 외부 도메인으로의 리다이렉트
           - HTTP/HTTPS 혼용으로 인한 보안 취약점
           - iframe을 통한 외부 콘텐츠 삽입

        10. **사회공학적 기법**
           - 긴급성을 조장하는 문구 사용
           - 공포감이나 불안감 조성
           - 단축 URL 사용으로 실제 목적지 은폐

        11. **첨부파일 분석** (첨부파일이 있는 경우)
           - 실행 파일(.exe, .bat, .scr 등) 포함 여부
           - 압축 파일 내 의심 파일 가능성
           - 문서 파일의 매크로 포함 가능성
           - 파일명과 실제 타입의 불일치 여부

        [응답 형식]
        반드시 다음 형식으로 응답하세요:

        PHISHING: YES 또는 NO
        CONFIDENCE: 0.0-1.0
        RISK_CATEGORIES: [확인된 위험 카테고리들]
        MATCHED_PATTERNS: [학습된 패턴 중 매칭된 것들]
        DETAILED_ANALYSIS: 
        - 도메인 분석: [구체적인 도메인 위험 요소]
        - 폼 분석: [입력 폼의 위험성]
        - 스크립트 분석: [JavaScript 위험 요소]
        - 리다이렉트 분석: [리다이렉트 패턴]
        - 패턴 매칭: [학습된 패턴과의 일치도]
        - 종합 판단: [최종 파밍 여부 판단 근거]
        """
    
    def calculate_pattern_score(self, email_text: str) -> float:
        """학습된 패턴과 매칭하여 점수 계산"""
        if not self.knowledge_base:
            return 50.0
        
        score = 0
        matched_patterns = []
        
        # 위험 키워드 매칭
        text_lower = email_text.lower()
        for word, stats in self.knowledge_base.patterns['keywords'].items():
            if word in text_lower:
                score += stats['ratio'] * 5
                matched_patterns.append(f"keyword:{word}")
        
        # 의심 도메인 매칭
        for domain, count in self.knowledge_base.patterns['domains'].items():
            if domain in email_text:
                if count > 10:
                    score += 15
                    matched_patterns.append(f"domain:{domain}")
        
        # 한국어 패턴 매칭
        if 'korean_patterns' in self.knowledge_base.patterns:
            kp = self.knowledge_base.patterns['korean_patterns']
            
            # 긴급성 키워드
            for keyword in kp['urgent_keywords']:
                if keyword in email_text:
                    score += 10
                    matched_patterns.append(f"korean_urgent:{keyword}")
            
            # 인증 키워드
            for keyword in kp['credential_keywords']:
                if keyword in email_text:
                    score += 12
                    matched_patterns.append(f"korean_credential:{keyword}")
        
        # HTML 패턴 매칭
        if '<form' in email_text.lower():
            html_patterns = self.knowledge_base.patterns.get('html_patterns', {})
            form_ratio = html_patterns.get('form_ratio', 0)
            if form_ratio > 0.3:
                score += 20
                matched_patterns.append("high_form_ratio")
        
        # 점수 정규화 (0-100)
        final_score = min(100, score)
        
        logger.info(f"패턴 매칭 결과: {len(matched_patterns)}개 일치, 점수: {final_score}")
        logger.debug(f"매칭된 패턴: {matched_patterns[:10]}")
        
        return final_score
   
    def remove_code_and_css(self, text):
        """자연어처리 전용: 코드, 스타일, 태그 등 제거"""
        # <style>, <script> 블록 전체 삭제
        text = re.sub(r'<style.*?>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # 인라인 style="..." 제거
        text = re.sub(r'style="[^"]*"', '', text, flags=re.IGNORECASE)
        # CSS 속성 선언부 margin: 0; 등 삭제
        text = re.sub(r'\b[a-zA-Z0-9_-]+\s*:\s*[^;{]+[;}]', '', text)
        # HTML 태그 전체 삭제
        text = re.sub(r'<[^>]+>', ' ', text)
        return text

    def setup_nlp_models(self):
        """NLP 모델 초기화"""
        self.spacy_nlp = None
        self.spacy_nlp_ko = None
        self.spacy_nlp_en = None  
        
        # 영어 모델 로드
        if SPACY_AVAILABLE:
            try:
                self.spacy_nlp_en = spacy.load("en_core_web_sm")
                self.spacy_nlp = self.spacy_nlp_en
                logger.info("영어 SpaCy NLP 모델 로드 성공")
            except:
                logger.warning("영어 SpaCy 모델 로드 실패")
        
        # 한국어 모델 로드
        try:
            self.spacy_nlp_ko = spacy.load("ko_core_news_sm")
            logger.info("한국어 SpaCy NLP 모델 로드 성공")
        except:
            logger.warning("한국어 SpaCy 모델 로드 실패 - 'python -m spacy download ko_core_news_sm' 필요")

    def filter_konlpy_results(self, konlpy_results: List[str], original_text: str) -> Set[str]:
        """KoNLPy 결과를 통계적/언어학적 방법으로 필터링"""
        logger.info(f"filter_konlpy_results 시작: {len(konlpy_results)}개 처리")
        logger.info(f"원본 KoNLPy 결과: {konlpy_results}")
        
        # 1. 복합어 병합 처리
        compound_words = {
            ('에브리', '타임'): '에브리타임',
            ('카카오', '톡'): '카카오톡',
            ('네이버', '페이'): '네이버페이',
            ('삼성', '페이'): '삼성페이',
            ('국민', '은행'): '국민은행',
            ('삼성', '전자'): '삼성전자'
        }
        
        # 병합 처리
        merged_results = []
        skip_next = False
        
        for i, word in enumerate(konlpy_results):
            if skip_next:
                skip_next = False
                continue
                
            if i + 1 < len(konlpy_results):
                next_word = konlpy_results[i + 1]
                pair = (word, next_word)
                
                if pair in compound_words:
                    merged_results.append(compound_words[pair])
                    skip_next = True
                    logger.info(f"복합어 병합: {pair} -> {compound_words[pair]}")
                    continue
            
            merged_results.append(word)
        
        logger.info(f"병합 후 결과: {merged_results}")
        
        # 2. 기존 필터링 로직 적용
        filtered = set()
        
        # 제외 단어 리스트
        exclude_words = ['회원', '본인', '일시', '주소', '활동', '기기']
        
        for entity in merged_results:
            entity = entity.strip()
            
            # 길이 체크
            if len(entity) < 2 or len(entity) > 20:
                continue
            
            # 제외 단어 체크
            if entity in exclude_words:
                continue
            
            # 엔트로피 기반 필터링 (기존 로직)
            if hasattr(self, 'calculate_entropy'):
                if self.calculate_entropy(entity) < 1.0:
                    continue
            
            # 문맥 기반 점수 계산 (기존 로직)
            if hasattr(self, 'calculate_context_score'):
                context_score = self.calculate_context_score(entity, original_text)
                if context_score > 0.5:
                    filtered.add(entity)
                    continue
            
            # 통계적 유의성 확인 (기존 로직)
            if hasattr(self, 'is_statistically_significant'):
                if self.is_statistically_significant(entity, original_text):
                    filtered.add(entity)
            else:
                # 폴백: 기본 필터 (브랜드 가능성)
                brand_suffixes = ['청', '부', '원', '국', '사', '은행', '톡', '페이']
                if any(suffix in entity for suffix in brand_suffixes):
                    filtered.add(entity)
                # 복합어로 병합된 것들은 대부분 브랜드
                elif entity in compound_words.values():
                    filtered.add(entity)
        
        logger.info(f"filter_konlpy_results 완료: {len(filtered)}개 선택")
        logger.info(f"최종 필터링 결과: {list(filtered)}")
        
        return filtered
    
    def calculate_entropy(self, text: str) -> float:
        """텍스트의 엔트로피 계산 (다양성 측정)"""
        from collections import Counter
        import math
        
        if not text:
            return 0
        
        # 문자 빈도 계산
        char_freq = Counter(text)
        total_chars = len(text)
        
        # 엔트로피 계산
        entropy = 0
        for count in char_freq.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def calculate_context_score(self, entity: str, full_text: str) -> float:
        """문맥 기반 브랜드 가능성 점수 계산"""
        score = 0.0
        
        if entity not in full_text:
            return 0.0
        
        # 위치 기반 점수 (문서 앞부분에 나오면 가중치)
        position = full_text.find(entity)
        position_score = 1.0 - (position / len(full_text))
        score += position_score * 0.3
        
        # 대소문자 패턴 점수
        if entity and entity[0].isupper():  # 첫 글자 대문자
            score += 0.2
        
        # 주변 문맥 분석
        window_size = 50
        start = max(0, position - window_size)
        end = min(len(full_text), position + len(entity) + window_size)
        context = full_text[start:end]
        
        # 이메일 헤더 패턴 근처
        header_patterns = ['From:', '발신:', 'Subject:', '제목:', '@', '.com', '.kr', '.net']
        for pattern in header_patterns:
            if pattern in context:
                score += 0.1
        
        # 특수 기호 근처 (브랜드 표시)
        brand_markers = ['©', '™', '®', '【', '】', '「', '」', '"', "'"]
        for marker in brand_markers:
            if marker in context:
                score += 0.15
        
        return min(score, 1.0)

    def is_statistically_significant(self, entity: str, full_text: str) -> bool:
        """통계적으로 유의미한 엔티티인지 판단"""
        # TF-IDF 개념 적용
        entity_count = full_text.count(entity)
        text_length = len(full_text.split())
        
        # 빈도가 너무 높거나 낮으면 제외
        frequency = entity_count / max(text_length, 1)
        if frequency > 0.1 or frequency < 0.001:  # 10% 이상 또는 0.1% 미만
            return False
        
        # 문자 구성 다양성
        unique_chars = len(set(entity))
        if unique_chars < 2:  # 너무 단순
            return False
        
        return True

    def final_filter_brands(self, brands: Set[str]) -> Set[str]:
        """최종 필터링 (머신러닝 기반 점수)"""
        final_brands = set()
        
        for brand in brands:
            brand = brand.strip()
            
            # 기본 유효성 검사
            if not brand or len(brand) < 2 or len(brand) > 30:
                continue
            
            # 숫자만 있는 경우 제외
            if brand.isdigit():
                continue
            
            # 품질 점수 계산
            quality_score = self.calculate_brand_quality_score(brand)
            
            # 임계값 이상만 유지
            if quality_score > 0.6:
                final_brands.add(brand)
        
        return final_brands

    def calculate_brand_quality_score(self, brand: str) -> float:
        """브랜드 품질 점수 계산 (0~1)"""
        score = 0.0
        
        # 0. 알려진 실제 브랜드는 높은 점수
        KNOWN_BRANDS = {'핵테온', '카카오', '네이버', '쿠팡', '배민'}
        if brand.lower() in KNOWN_BRANDS or brand in KNOWN_BRANDS:
            return 0.9  # 높은 점수 보장
        
        # 1. 길이 점수
        length = len(brand)
        if 3 <= length <= 15:
            score += 0.3
        elif 2 <= length <= 20:
            score += 0.1
        
        # 2. 고유명사 패턴
        if any(brand.endswith(suffix) for suffix in ['은행', '카드', '증권', '보험', '전자']):
            score += 0.4
        
        # 3. 일반 명사 감점
        common_nouns = ['이메일', '대학생', '참가자', '사이버', '국제', '경진', '대회', '안내', '보안']
        if brand in common_nouns:
            score -= 0.5
        
        # 4. 한글 고유명사 형태 (받침 있는 3글자 이상)
        if len(brand) >= 3 and all('가' <= c <= '힣' for c in brand):
            score += 0.2  
        
        return max(0, min(score, 1.0))
    
    def extract_brand_entities(self, text: str) -> Set[str]:
        """텍스트에서 브랜드/조직 엔티티 추출 (완성 버전)"""
        logger.info(f"extract_brand_entities 호출됨, 텍스트 길이: {len(text)}")
        brands = set()
        
        # 일반 단어 블랙리스트 (브랜드가 아닌 것들)
        BLACKLIST = {
            '이메일', '메일', '대학생', '참가자', '참가', '안내', '사이버',
            '국제', '경진', '대회', '보안', '행사', '공지', '알림',
            '회원', '본인', '일시', '주소', '활동', '기기', '계정',
            '비밀번호', '로그인', '클릭', '확인', '신청', '접수'
        }
        
        # 텍스트 인코딩 정리
        try:
            if 'ì' in text or 'ë' in text or 'í' in text:
                try:
                    text_fixed = text.encode('latin-1').decode('utf-8', errors='ignore')
                    if text_fixed and len(text_fixed) > 10:
                        text = text_fixed
                        logger.info("텍스트 인코딩 복구 성공")
                except:
                    logger.warning("텍스트 인코딩 복구 실패, 원본 사용")
                    text = ''.join(c for c in text if c.isprintable() or c.isspace())
        except Exception as e:
            logger.error(f"텍스트 인코딩 처리 중 오류: {e}")
        
        # 1. 정규식 패턴 매칭 (안전함)
        logger.info("정규식 패턴 매칭 시작")
        regex_brands = set()
        try:
            patterns = [
                r'(한국\s*우편|우체국)',
                r'([가-힣]{2,10})(?:은행|카드|증권|보험|항공|전자|백화점)',
                r'["\'"]([^"\']+)["\'"]',
            ]
            
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, str) and 2 <= len(match) <= 30:
                            brand = match.strip()
                            if brand and not brand.isdigit():
                                regex_brands.add(brand)
                except:
                    continue
            
            brands.update(regex_brands)
            logger.info(f"정규식으로 {len(regex_brands)}개 추출: {list(regex_brands)}")
        except Exception as e:
            logger.error(f"정규식 처리 오류: {e}")
        
        # 2. SpaCy 시도
        spacy_brands = set()
        if hasattr(self, 'spacy_nlp_ko') and self.spacy_nlp_ko:
            try:
                safe_text = text[:500]
                doc = self.spacy_nlp_ko(safe_text)
                for ent in doc.ents:
                    if ent.label_ in ['ORG', 'PERSON', 'LOC', 'PRODUCT']:
                        spacy_brands.add(ent.text.strip())
                
                logger.info(f"SpaCy 추출 결과: {list(spacy_brands)}")
                
                # 필터링 적용
                filtered_spacy = set()
                for brand in spacy_brands:
                    if 2 <= len(brand) <= 30 and not brand.isdigit():
                        # 품질 점수 확인
                        if hasattr(self, 'calculate_brand_quality_score'):
                            score = self.calculate_brand_quality_score(brand)
                            if score > 0.3:
                                filtered_spacy.add(brand)
                                logger.debug(f"SpaCy '{brand}' 통과 (점수: {score})")
                            else:
                                logger.debug(f"SpaCy '{brand}' 제외 (점수: {score})")
                        else:
                            filtered_spacy.add(brand)
                
                brands.update(filtered_spacy)
                logger.info(f"SpaCy로 {len(filtered_spacy)}개 추가 (필터링 후)")
            except Exception as e:
                logger.warning(f"SpaCy 처리 오류: {e}")
        
        # 3. KoNLPy 
        konlpy_brands = set()
        try:
            safe_text_for_konlpy = re.sub(r'[^\w\s가-힣]', ' ', text[:300])
            if safe_text_for_konlpy and len(safe_text_for_konlpy) > 10:
                logger.info("KoNLPy 시도 중...")
                
                import subprocess
                import sys
                import json
                import tempfile
                import os
                import textwrap
                
                # 임시 파일로 스크립트 저장
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                    script_path = f.name
                    script_content = textwrap.dedent("""
                        import json
                        import sys
                        
                        try:
                            from konlpy.tag import Okt
                            okt = Okt()
                            
                            text = sys.argv[1] if len(sys.argv) > 1 else ''
                            pos = okt.pos(text)
                            nouns = [w for w, t in pos if t in ['Noun', 'ProperNoun'] and len(w) >= 2]
                            
                            print(json.dumps(nouns[:20], ensure_ascii=False))
                            
                        except Exception as e:
                            import traceback
                            error_info = {
                                "error": str(e),
                                "traceback": traceback.format_exc()
                            }
                            print(json.dumps(error_info, ensure_ascii=False))
                            sys.exit(1)
                    """).strip()
                    
                    f.write(script_content)
                
                try:
                    # 환경변수 설정 (UTF-8 강제)
                    env = os.environ.copy()
                    env['PYTHONIOENCODING'] = 'utf-8'
                    
                    # 스크립트 파일 실행 (바이트로 받기)
                    result = subprocess.run(
                        [sys.executable, script_path, safe_text_for_konlpy],
                        capture_output=True,
                        text=False,  # 바이트로 받기
                        env=env,  # UTF-8 환경변수
                        timeout=100,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    
                    logger.debug(f"KoNLPy 리턴코드: {result.returncode}")
                    
                    # stderr 디코딩 (cp949 폴백)
                    if result.stderr:
                        try:
                            stderr_text = result.stderr.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                stderr_text = result.stderr.decode('cp949')
                            except:
                                stderr_text = result.stderr.decode('utf-8', errors='ignore')
                        
                        if stderr_text.strip():
                            logger.error(f"KoNLPy stderr: {stderr_text}")
                    
                    # stdout 디코딩 (cp949 폴백)
                    if result.stdout:
                        try:
                            stdout_text = result.stdout.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                stdout_text = result.stdout.decode('cp949')
                            except:
                                stdout_text = result.stdout.decode('utf-8', errors='ignore')
                        
                        logger.debug(f"KoNLPy stdout: {stdout_text[:500]}")
                        
                        try:
                            # 에러 체크
                            if result.returncode != 0:
                                error_data = json.loads(stdout_text)
                                logger.error(f"KoNLPy 실행 오류: {error_data}")
                            else:
                                # 정상 결과
                                konlpy_results = json.loads(stdout_text.strip())
                                logger.info(f"KoNLPy 추출 성공: {konlpy_results}")
                                
                                # 필터링 적용 (안전하게 처리)
                                try:
                                    if hasattr(self, 'filter_konlpy_results'):
                                        logger.info("filter_konlpy_results 호출 시작")
                                        filtered_konlpy = self.filter_konlpy_results(konlpy_results, text)
                                        logger.info(f"filter_konlpy_results 완료: {filtered_konlpy}")
                                        konlpy_brands.update(filtered_konlpy)
                                        logger.info(f"KoNLPy 필터링 후: {list(filtered_konlpy)}")
                                    else:
                                        # filter_konlpy_results가 없으면 결과 모두 저장
                                        logger.info("filter_konlpy_results 함수 없음, 기본 필터링 사용")
                                        for entity in konlpy_results:
                                            if isinstance(entity, str) and 2 <= len(entity) <= 20:
                                                konlpy_brands.add(entity)
                                                logger.debug(f"KoNLPy 브랜드 키워드 매칭: {entity}")
                                        logger.info(f"기본 필터링 후 KoNLPy: {list(konlpy_brands)}")
                                except Exception as filter_error:
                                    logger.error(f"KoNLPy 필터링 중 오류: {filter_error}")
                                    # 필터링 실패 시 최소한의 처리
                                    for entity in konlpy_results[:10]:  # 최대 10개만
                                        if isinstance(entity, str) and 2 <= len(entity) <= 20:
                                            konlpy_brands.add(entity)
                                        
                        except json.JSONDecodeError as e:
                            logger.error(f"JSON 파싱 오류: {e}")
                            logger.error(f"원본: {stdout_text[:200]}")
                    else:
                        logger.warning("KoNLPy stdout 비어있음")
                        
                except subprocess.TimeoutExpired:
                    logger.warning("KoNLPy 타임아웃")
                except Exception as e:
                    logger.error(f"subprocess 실행 오류: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                finally:
                    # 임시 파일 삭제
                    try:
                        os.unlink(script_path)
                    except Exception as del_error:
                        logger.debug(f"임시 파일 삭제 실패: {del_error}")
                
                brands.update(konlpy_brands)
                logger.info(f"KoNLPy로 {len(konlpy_brands)}개 추가: {list(konlpy_brands)}")
                
        except Exception as e:
            logger.error(f"KoNLPy 처리 중 예외: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        # 4. 최종 필터링
        final_brands = set()
        for brand in brands:
            brand = brand.strip()
            
            # 블랙리스트 체크
            if brand in BLACKLIST:
                logger.debug(f"블랙리스트 단어 제외: {brand}")
                continue
            
            # 기존 검증 로직
            if 2 <= len(brand) <= 30 and not brand.isdigit():
                if hasattr(self, 'calculate_brand_quality_score'):
                    score = self.calculate_brand_quality_score(brand)
                    if score > 0.4:
                        final_brands.add(brand)
                else:
                    final_brands.add(brand)
        
        return final_brands
    
    async def search_official_website(self, brand_name: str) -> List[str]:
        """브랜드의 공식 웹사이트를 웹 검색으로 찾기"""
        if brand_name in self.official_sites_cache:
            return self.official_sites_cache[brand_name]
        
        official_sites = []
        
        try:
            # DuckDuckGo API 사용 (무료, 제한 없음)
            search_url = f"https://duckduckgo.com/html/"
            params = {
                'q': f"{brand_name} official website",
                'kl': 'kr-kr'  # 한국 지역 설정
            }
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(search_url, params=params, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # DuckDuckGo 검색 결과에서 링크 추출
                        search_results = soup.find_all('a', class_='result__a')
                        
                        for result in search_results[:5]:  # 상위 5개 결과
                            href = result.get('href')
                            if href:
                                # DuckDuckGo 리다이렉트 URL에서 실제 URL 추출
                                if 'uddg=' in href:
                                    import urllib.parse
                                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                                    if 'uddg' in parsed:
                                        actual_url = urllib.parse.unquote(parsed['uddg'][0])
                                        official_sites.append(actual_url)
                                        logger.info(f"DuckDuckGo에서 찾은 URL: {actual_url}")
                                else:
                                    official_sites.append(href)
            
            # Bing Search API 사용 (대안)
            if not official_sites:
                bing_url = f"https://www.bing.com/search"
                params = {'q': f"{brand_name} official site"}
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(bing_url, params=params, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            html = await response.text()
                            # Bing 결과에서 URL 패턴 찾기
                            urls = re.findall(r'<cite>(https?://[^<]+)</cite>', html)
                            official_sites.extend(urls[:3])
            
            # Wikipedia API로 공식 웹사이트 찾기
            wiki_api_url = "https://ko.wikipedia.org/w/api.php"
            params = {
                'action': 'query',
                'format': 'json',
                'titles': brand_name,
                'prop': 'extlinks',
                'ellimit': 'max'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(wiki_api_url, params=params, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        pages = data.get('query', {}).get('pages', {})
                        for page_id, page_data in pages.items():
                            if 'extlinks' in page_data:
                                for link in page_data['extlinks']:
                                    url = link.get('*', '')
                                    if 'official' in url.lower() or brand_name.lower() in url.lower():
                                        official_sites.append(url)
                                        logger.info(f"Wikipedia에서 찾은 공식 사이트: {url}")
            
            # DNS 기반 직접 확인 (도메인 추론)
            possible_domains = [
                f"https://www.{brand_name.lower().replace(' ', '')}.com",
                f"https://www.{brand_name.lower().replace(' ', '')}.co.kr",
                f"https://www.{brand_name.lower().replace(' ', '')}.kr",
                f"https://www.{brand_name.lower().replace(' ', '')}.go.kr",
                f"https://{brand_name.lower().replace(' ', '')}.com",
                f"https://{brand_name.lower().replace(' ', '')}.co.kr",
            ]
            
            # 특수 케이스 처리 (정부기관 등)
            if any(keyword in brand_name for keyword in ['우체국', '국세청', '정부', '공사', '공단']):
                possible_domains.extend([
                    f"https://www.{brand_name.lower().replace(' ', '')}.go.kr",
                    f"https://{brand_name.lower().replace(' ', '')}.go.kr"
                ])
            
            for domain in possible_domains:
                try:
                    timeout = aiohttp.ClientTimeout(total=3)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.head(domain, allow_redirects=True, ssl=False) as response:
                            if response.status in [200, 301, 302]:
                                final_url = str(response.url)
                                if final_url not in official_sites:
                                    official_sites.append(final_url)
                                    logger.info(f"도메인 직접 확인 성공: {final_url}")
                except:
                    continue
            
            # 중복 제거
            official_sites = list(set(official_sites))
            
            # 캐시에 저장
            self.official_sites_cache[brand_name] = official_sites
            
            if official_sites:
                logger.info(f"브랜드 '{brand_name}'의 공식 사이트 {len(official_sites)}개 발견")
            else:
                logger.warning(f"브랜드 '{brand_name}'의 공식 사이트를 찾지 못함")
            
        except Exception as e:
            logger.error(f"공식 웹사이트 검색 오류 (브랜드: {brand_name}): {e}")
        
        return official_sites
    
    def calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """두 도메인 간의 유사도 계산 (0~1)"""
        from difflib import SequenceMatcher
        
        # 도메인 정규화
        d1 = domain1.lower().replace('www.', '').replace('https://', '').replace('http://', '')
        d2 = domain2.lower().replace('www.', '').replace('https://', '').replace('http://', '')
        
        # 완전 일치
        if d1 == d2:
            return 1.0
        
        # 부분 문자열 포함
        if d1 in d2 or d2 in d1:
            return 0.8
        
        # 문자열 유사도 계산
        similarity = SequenceMatcher(None, d1, d2).ratio()
        
        # 타이포스쿼팅 탐지 (유사하지만 다른 도메인)
        if 0.7 < similarity < 0.95:
            logger.warning(f"타이포스쿼팅 의심: {domain1} vs {domain2} (유사도: {similarity:.2f})")
        
        return similarity
    
    async def analyze_brand_matching(self, email_data: Dict) -> Dict:
        """브랜드 매칭 분석을 통한 피싱 탐지"""
        result = {
            'extracted_brands': [],
            'official_sites': {},
            'suspicious_domains': [],
            'typosquatting_detected': False
            
        }
        
        try:
            # 1. 자연어처리용 본문(정제)
            subject = email_data.get('subject', '') or ''
            body_html = email_data.get('body', '') or ''
            body_clean = self.remove_code_and_css(body_html)
            full_text = f"{subject} {body_clean}"
            brands = self.extract_brand_entities(full_text)
            result['extracted_brands'] = list(brands)
            
            # 2. 각 브랜드의 공식 웹사이트 검색
            for brand in brands:
                official_sites = await self.search_official_website(brand)
                if official_sites:
                    result['official_sites'][brand] = official_sites
                    
            # 3. 이메일 내 URL과 공식 사이트 비교
            email_urls = self.extract_urls_from_body(email_data.get('body', ''))
            
            for email_url in email_urls:
                email_domain = urlparse(email_url).netloc
                is_suspicious = True
                max_similarity = 0
                
                for brand, official_urls in result['official_sites'].items():
                    for official_url in official_urls:
                        official_domain = urlparse(official_url).netloc
                        similarity = self.calculate_domain_similarity(email_domain, official_domain)
                        max_similarity = max(max_similarity, similarity)
                        
                        # 공식 도메인과 일치
                        if similarity > 0.95:
                            is_suspicious = False
                            break
                        # 타이포스쿼팅 의심
                        elif 0.7 < similarity < 0.95:
                            result['typosquatting_detected'] = True
                            result['suspicious_domains'].append({
                                'url': email_url,
                                'similar_to': official_url,
                                'similarity': similarity,
                                'brand': brand
                            })
                
                # 브랜드는 언급되었지만 URL이 전혀 매칭되지 않음
                if is_suspicious and max_similarity < 0.3 and result['extracted_brands']:
                    result['suspicious_domains'].append({
                        'url': email_url,
                        'reason': '브랜드와 무관한 도메인',
                        'brands_mentioned': result['extracted_brands']
                    })
            
                        
            # 브랜드는 언급되었지만 공식 사이트 링크가 없는 경우
            if result['extracted_brands'] and not any(
                self.calculate_domain_similarity(urlparse(url).netloc, urlparse(official).netloc) > 0.95
                for url in email_urls
                for brand_sites in result['official_sites'].values()
                for official in brand_sites
            ):
                pass
                
        except Exception as e:
            logger.error(f"브랜드 매칭 분석 오류: {e}")
        
        return result
    
    def is_external_domain(self, url, current_domain):
        """URL이 외부 도메인인지 확인"""
        try:
            from urllib.parse import urlparse
            url_domain = urlparse(url).netloc
            return url_domain and url_domain != current_domain and not url.startswith('/')
        except:
            return False
    
    def check_indentation_consistency(self, html_str):
        """HTML 들여쓰기 일관성 점수 (0-1)"""
        lines = html_str.split('\n')
        indented_lines = [line for line in lines if line.strip() and line.startswith((' ', '\t'))]
        
        if len(lines) < 10:  # 너무 짧은 HTML
            return 0.5
        
        consistency_score = len(indented_lines) / len(lines) if lines else 0
        return min(consistency_score, 1.0)
    
    def extract_current_domain(self, soup):
        """현재 페이지의 도메인 추출"""
        try:
            # base 태그에서 도메인 추출 시도
            base_tag = soup.find('base', href=True)
            if base_tag:
                from urllib.parse import urlparse
                return urlparse(base_tag['href']).netloc
            
            # canonical URL에서 추출 시도
            canonical = soup.find('link', rel='canonical')
            if canonical and canonical.get('href'):
                from urllib.parse import urlparse
                return urlparse(canonical['href']).netloc
        except:
            pass
        return ''
    
    def analyze_structural_patterns(self, soup):
        """HTML 구조적 패턴으로 파밍 사이트 감지"""
        patterns = {
            'form_to_content_ratio': 0,
            'external_form_actions': 0,
            'hidden_field_ratio': 0,
            'script_complexity_score': 0,
            'redirect_chain_length': 0,
            'resource_domain_diversity': 0
        }
        
        # 폼 대 콘텐츠 비율 (파밍 사이트는 폼 비중이 높음)
        forms = soup.find_all('form')
        total_content = len(soup.get_text())
        if total_content > 0:
            form_content = sum(len(form.get_text()) for form in forms)
            patterns['form_to_content_ratio'] = form_content / total_content
        
        # 외부 도메인으로 향하는 폼 액션
        current_domain = self.extract_current_domain(soup)
        for form in forms:
            action = form.get('action', '')
            if action and self.is_external_domain(action, current_domain):
                patterns['external_form_actions'] += 1
        
        # 숨겨진 필드 비율
        inputs = soup.find_all('input')
        if inputs:
            hidden_inputs = [inp for inp in inputs if inp.get('type') == 'hidden']
            patterns['hidden_field_ratio'] = len(hidden_inputs) / len(inputs)
        
        return patterns
    
    def analyze_behavioral_patterns(self, soup):
        """사용자 행동을 유도하는 패턴 분석"""
        behavioral_signals = {
            'input_field_urgency': 0,
            'visual_emphasis_score': 0,
            'cognitive_load_score': 0,
            'trust_signal_absence': 0
        }
        
        # 입력 필드의 시급성 (required, autofocus 등)
        inputs = soup.find_all('input')
        urgent_inputs = [inp for inp in inputs 
                        if inp.get('required') or inp.get('autofocus')]
        if inputs:
            behavioral_signals['input_field_urgency'] = len(urgent_inputs) / len(inputs)
        
        # 시각적 강조 요소 (색상, 크기, 애니메이션 등)
        emphasized_elements = soup.find_all(['b', 'strong', 'em', 'mark'])
        emphasized_elements += soup.find_all(attrs={'style': lambda x: x and 
                                                   any(prop in x.lower() for prop in 
                                                      ['color:red', 'font-weight:bold', 'blink'])})
        behavioral_signals['visual_emphasis_score'] = len(emphasized_elements)
        
        return behavioral_signals
    
    def analyze_technical_fingerprint(self, soup):
        """기술적 구현 패턴으로 파밍 사이트 특성 분석"""
        fingerprint = {
            'framework_indicators': [],
            'code_quality_score': 0,
            'obfuscation_level': 0,
            'resource_integrity_score': 0
        }
        
        # 프레임워크/도구 감지
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            content = script.string or ''
            
            # 합법적 프레임워크 vs 수상한 스크립트 구분
            if any(framework in src for framework in 
                   ['jquery', 'bootstrap', 'react', 'vue', 'angular']):
                fingerprint['framework_indicators'].append('legitimate')
            elif any(pattern in content for pattern in 
                    ['eval(', 'unescape(', 'fromCharCode']):
                fingerprint['obfuscation_level'] += 1
        
        # 코드 품질 점수 (들여쓰기, 주석, 구조 등)
        html_str = str(soup)
        indentation_consistency = self.check_indentation_consistency(html_str)
        has_comments = '<!--' in html_str
        fingerprint['code_quality_score'] = indentation_consistency + (0.2 if has_comments else 0)
        
        return fingerprint
    
    def analyze_domain_relationships(self, soup):
        """도메인 간 관계와 신뢰성 분석"""
        domain_analysis = {
            'primary_domain': '',
            'referenced_domains': set(),
            'domain_age_indicators': [],
            'ssl_consistency': True,
            'subdomain_patterns': []
        }
        
        # 모든 URL에서 도메인 추출
        all_urls = []
        for tag in soup.find_all(['a', 'img', 'script', 'link', 'form']):
            url = tag.get('href') or tag.get('src') or tag.get('action')
            if url and url.startswith('http'):
                all_urls.append(url)
        
        # 도메인 다양성 분석
        from urllib.parse import urlparse
        domains = set()
        for url in all_urls:
            domain = urlparse(url).netloc
            if domain:
                domains.add(domain)
                domain_analysis['referenced_domains'].add(domain)
        
        # SSL 일관성 체크
        http_count = sum(1 for url in all_urls if url.startswith('http://'))
        https_count = sum(1 for url in all_urls if url.startswith('https://'))
        domain_analysis['ssl_consistency'] = http_count == 0  # 모두 HTTPS여야 함
        
        return domain_analysis
    
    def calculate_risk_indicators(self, features):
        """패턴 기반 위험 지표 계산"""
        indicators = []
        
        # 구조적 위험
        if features['structural_patterns'].get('form_to_content_ratio', 0) > 0.3:
            indicators.append('high_form_ratio')
        
        if features['structural_patterns'].get('external_form_actions', 0) > 0:
            indicators.append('external_form_submission')
        
        # 기술적 위험
        if features['technical_fingerprint'].get('obfuscation_level', 0) > 0:
            indicators.append('code_obfuscation')
        
        if not features['domain_relationships'].get('ssl_consistency', True):
            indicators.append('mixed_ssl_content')
        
        return indicators
    
    def extract_html_features(self, html: str) -> Dict[str, Any]:
        """고급 파밍 사이트 탐지를 위한 패턴 기반 특징 추출"""
        features = {
            'basic_info': {},
            'structural_patterns': {},
            'behavioral_patterns': {},
            'technical_fingerprint': {},
            'domain_relationships': {},
            'risk_indicators': []
        }
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 기본 정보
            features['basic_info'] = {
                'title': soup.find('title').text[:100] if soup.find('title') else '',
                'forms_count': len(soup.find_all('form')),
                'links_count': len(soup.find_all('a')),
                'scripts_count': len(soup.find_all('script')),
                'content_length': len(soup.get_text())
            }
            
            # 구조적 패턴 분석
            features['structural_patterns'] = self.analyze_structural_patterns(soup)
            
            # 행동 유도 패턴 분석
            features['behavioral_patterns'] = self.analyze_behavioral_patterns(soup)
            
            # 기술적 지문 분석
            features['technical_fingerprint'] = self.analyze_technical_fingerprint(soup)
            
            # 도메인 관계 분석
            features['domain_relationships'] = self.analyze_domain_relationships(soup)
            
            # 종합 위험 지표 계산
            features['risk_indicators'] = self.calculate_risk_indicators(features)
            
        except Exception as e:
            logger.error(f"HTML 특징 추출 오류: {e}")
            features['error'] = str(e)
        
        return features
    
    def _format_html_analysis(self, header_features, body_features):
        """HTML 분석 결과를 읽기 쉽게 포맷팅"""
        analysis = []
        
        if header_features:
            analysis.append("정상 사이트 추정 특징:")
            for url, features in header_features.items():
                analysis.append(f"- {url}: {features.get('basic_info', {})}")
        
        if body_features:
            analysis.append("의심 사이트 특징:")
            for url, features in body_features.items():
                analysis.append(f"- {url}: {features.get('risk_indicators', [])}")
        
        return "\n".join(analysis) if analysis else "HTML 분석 데이터 없음"
    
    def setup_ai_clients(self):
        """AI 클라이언트 설정"""
        self.anthropic_client = None
            
        try:
            if ANTHROPIC_AVAILABLE and ANTHROPIC_API_KEY:
                self.anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                logger.info("Anthropic 클라이언트 초기화 성공")
        except Exception as e:
            logger.warning(f"Anthropic 클라이언트 초기화 실패: {e}")
    
    def extract_urls_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """이메일 헤더에서 발신 도메인 기반 정상 사이트 URL 추출"""
        legitimate_urls = []
        
        # 1. 발신자 도메인 추출
        sender_domain = self.get_sender_domain(headers)
        if not sender_domain:
            logger.warning("발신자 도메인을 찾을 수 없습니다.")
            return legitimate_urls
        
        logger.info(f"발신자 도메인: {sender_domain}")
        
        # 2. 발신 도메인을 기반으로 정상적인 사이트들 동적 발견
        legitimate_sites = self.discover_legitimate_sites(sender_domain)
        legitimate_urls.extend(legitimate_sites)
        
        logger.info(f"헤더에서 {len(legitimate_urls)}개의 정상 사이트 URL 발견")
        return legitimate_urls
    
    def get_sender_domain(self, headers: Dict[str, str]) -> str:
        """발신자 도메인 추출"""
        # From 헤더에서 도메인 추출
        from_header = headers.get('From', '')
        if '@' in from_header:
            domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_header)
            if domain_match:
                return domain_match.group(1)
        
        # Return-Path에서도 시도
        return_path = headers.get('Return-Path', '')
        if '@' in return_path:
            domain_match = re.search(r'@([a-zA-Z0-9.-]+)', return_path)
            if domain_match:
                return domain_match.group(1)
        
        return ""

    def discover_legitimate_sites(self, sender_domain: str) -> List[str]:
        """발신 도메인을 기반으로 정상적인 사이트들을 동적으로 발견"""
        legitimate_sites = []
        
        try:
            # 1. 조직의 공식 웹사이트 추론
            official_sites = self.infer_official_websites(sender_domain)
            legitimate_sites.extend(official_sites)
            
            # 2. DNS 레코드를 통한 공식 사이트 발견
            dns_verified_sites = self.find_sites_via_dns(sender_domain)
            legitimate_sites.extend(dns_verified_sites)
            
            # 중복 제거
            legitimate_sites = list(set(legitimate_sites))
            
        except Exception as e:
            logger.error(f"정상 사이트 발견 중 오류: {e}")
        
        return legitimate_sites

    def infer_official_websites(self, sender_domain: str) -> List[str]:
        """발신 도메인으로부터 공식 웹사이트 추론"""
        inferred_sites = []
        
        try:
            # 메일 서브도메인에서 메인 도메인 추론
            if sender_domain.startswith('mail.'):
                base_domain = sender_domain.replace('mail.', '')
                inferred_sites.extend([f"https://www.{base_domain}", f"https://{base_domain}"])
            elif sender_domain.startswith('noreply.'):
                base_domain = sender_domain.replace('noreply.', '')
                inferred_sites.extend([f"https://www.{base_domain}", f"https://{base_domain}"])
            elif sender_domain.startswith('no-reply.'):
                base_domain = sender_domain.replace('no-reply.', '')
                inferred_sites.extend([f"https://www.{base_domain}", f"https://{base_domain}"])
            else:
                # 직접 도메인인 경우
                inferred_sites.extend([f"https://www.{sender_domain}", f"https://{sender_domain}"])
            
            # 실제 접근 가능한 사이트만 반환
            return self.verify_site_accessibility(inferred_sites)
            
        except Exception as e:
            logger.error(f"공식 웹사이트 추론 중 오류: {e}")
            return []

    def find_sites_via_dns(self, sender_domain: str) -> List[str]:
        """DNS 레코드를 통한 관련 사이트 발견"""
        dns_sites = []
        
        try:
            import dns.resolver
            
            # MX 레코드에서 관련 도메인 찾기
            try:
                mx_records = dns.resolver.resolve(sender_domain, 'MX')
                for mx in mx_records:
                    mx_domain = str(mx.exchange).rstrip('.')
                    if mx_domain != sender_domain:
                        # MX 서버 도메인에서 웹사이트 추론
                        base_mx = mx_domain.replace('mail.', '').replace('mx.', '')
                        dns_sites.extend([f"https://www.{base_mx}", f"https://{base_mx}"])
            except:
                pass
            
            # CNAME 레코드 확인
            try:
                cname_records = dns.resolver.resolve(f"www.{sender_domain}", 'CNAME')
                for cname in cname_records:
                    cname_target = str(cname.target).rstrip('.')
                    dns_sites.append(f"https://{cname_target}")
            except:
                pass
                
        except Exception as e:
            logger.error(f"DNS 기반 사이트 발견 중 오류: {e}")
        
        return self.verify_site_accessibility(dns_sites)

    def verify_site_accessibility(self, urls: List[str]) -> List[str]:
        """URL들이 실제 접근 가능한지 검증"""
        accessible_sites = []
        
        for url in urls:
            try:
                import requests
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    accessible_sites.append(url)
                    logger.info(f"접근 가능한 사이트 발견: {url}")
            except:
                continue
        
        return accessible_sites
    
    def extract_urls_from_body(self, body: str) -> List[str]:
        """이메일 본문에서 URL 추출 (base64 디코딩 포함)"""
        urls = []
        
        # base64로 인코딩된 경우 디코딩
        if 'Content-Transfer-Encoding: base64' in str(self.current_msg) if hasattr(self, 'current_msg') else False:
            try:
                import base64
                # base64 부분만 추출
                base64_pattern = re.compile(r'[A-Za-z0-9+/=]{50,}')
                base64_matches = base64_pattern.findall(body)
                for match in base64_matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        body = body + ' ' + decoded
                    except:
                        continue
            except:
                pass
        
        # 여러 URL 패턴 사용
        url_patterns = [
            # 표준 http/https URL
            r'https?://[^\s<>"\'{}|\\^`\[\]]+',
            # href 속성의 URL (작은따옴표, 큰따옴표 모두 처리)
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'href\s*=\s*([^\s>]+)',
            # src 속성의 URL
            r'src\s*=\s*["\']([^"\']+)["\']',
            r'src\s*=\s*([^\s>]+)',
            # Google Storage 특수 패턴
            r'(https?://storage\.googleapis\.com/[^\s<>"\']+)',
            r'(https?://storage\.googleapis\.com/[^\s<>"\']+)',
            # 앵커 태그 내의 URL (줄바꿈 포함)
            r'<a[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>',
        ]
        
        for pattern in url_patterns:
            try:
                matches = re.findall(pattern, body, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match.startswith('http'):
                        # URL 정리 (특수문자 제거)
                        clean_url = match.strip().rstrip('"\'>,')
                        urls.append(clean_url)
            except:
                continue
        
        # BeautifulSoup으로 추가 추출
        try:
            from bs4 import BeautifulSoup
            
            # HTML 파싱 (여러 파서 시도)
            soup = None
            for parser in ['html.parser', 'lxml', 'html5lib']:
                try:
                    soup = BeautifulSoup(body, parser)
                    break
                except:
                    continue
            
            if soup:
                # 모든 a 태그
                for link in soup.find_all('a', href=True):
                    href = link.get('href', '')
                    if href.startswith(('http://', 'https://')):
                        urls.append(href.strip())
                
                # 모든 img 태그
                for img in soup.find_all('img', src=True):
                    src = img.get('src', '')
                    if src.startswith(('http://', 'https://')):
                        urls.append(src.strip())
                
                # form 태그의 action
                for form in soup.find_all('form', action=True):
                    action = form.get('action', '')
                    if action.startswith(('http://', 'https://')):
                        urls.append(action.strip())
                        
        except Exception as e:
            logger.debug(f"BeautifulSoup 파싱 오류: {e}")
        
        # 멀티파트 이메일 처리
        if hasattr(self, 'current_msg') and self.current_msg:
            msg = self.current_msg
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type in ['text/html', 'text/plain']:
                        try:
                            part_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            # 재귀적으로 URL 추출
                            for pattern in url_patterns:
                                matches = re.findall(pattern, part_body, re.IGNORECASE | re.DOTALL)
                                for match in matches:
                                    if isinstance(match, tuple):
                                        match = match[0]
                                    if match.startswith('http'):
                                        urls.append(match.strip().rstrip('"\'>,'))
                        except:
                            continue
        
        # 중복 제거 및 정리
        unique_urls = []
        seen = set()
        for url in urls:
            # URL 정리
            url = url.strip()
            # 불필요한 문자 제거
            url = re.sub(r'[\s\n\r\t]', '', url)
            # HTML 엔티티 디코딩
            url = url.replace('&amp;', '&')
            
            if url not in seen and url.startswith('http'):
                seen.add(url)
                unique_urls.append(url)
        
        logger.info(f"본문에서 {len(unique_urls)}개의 URL 추출")
        if unique_urls:
            for i, url in enumerate(unique_urls[:5], 1):  # 처음 5개만 로깅
                logger.info(f"  {i}. {url[:100]}...")  # URL이 길 수 있으므로 100자만
        
        return unique_urls
        
    def analyze_with_multi_ai(self, email_data, initial_analysis):
        """AI로 이메일 분석 (1개 AI)"""
        try:
            if not AI_ENABLED:
                logger.info("AI 분석이 비활성화되어 있습니다.")
                return None
            
            # 비동기 분석 실행s
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def run_analysis():
                # 헤더 추출
                headers = {}
                if hasattr(self, 'current_msg'):
                    headers = dict(self.current_msg.items())
                
                # URL 추출 및 HTML 수집
                header_urls = self.extract_urls_from_headers(headers)
                body_urls = self.extract_urls_from_body(email_data.get('body', ''))
                
                # HTML 본문에서 추가 URL 추출
                if not body_urls and hasattr(self, 'result_dir'):
                    html_path = self.result_dir / "decoded_body.html"
                    if html_path.exists():
                        with open(html_path, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                            body_urls = self.extract_urls_from_body(html_content)
                
                # 헤더에서 실제 접속 가능한 도메인 찾기
                valid_header_urls = []
                for url in header_urls:
                    if url.startswith('http'):
                        valid_header_urls.append(url)
                
                # URL 내용 수집
                header_html_contents = {}
                body_html_contents = {}
                
                # 헤더 URL HTML 수집 (최대 2개)
                for url in valid_header_urls[:2]:
                    try:
                        logger.info(f"Fetching header URL: {url}")
                        html_content = await self.fetch_url_html(url)
                        if html_content:
                            header_html_contents[url] = html_content
                            logger.info(f"헤더 URL에서 데이터를 성공적으로 받아옴: {url} ({len(html_content)} bytes)")
                        else:
                            logger.warning(f"헤더 URL에서 받아올 데이터가 없음: {url}")
                    except Exception as e:
                        logger.error(f"헤더 URL을 가저올 수 없음 {url}: {str(e)}")
                
                # 본문 URL HTML 수집 (최대 3개)
                successful_body_urls = 0
                for url in body_urls:
                    if successful_body_urls >= 3:  # 최대 3개까지만
                        break
                        
                    if 'confirm.mail' not in url:  # 트래킹 URL 제외
                        try:
                            logger.info(f"바디 URL을 가져오는 중: {url}")
                            html_content = await self.fetch_url_html(url)
                            if html_content:
                                body_html_contents[url] = html_content
                                successful_body_urls += 1
                                logger.info(f"바디 URL에서 데이터를 성공적으로 받아옴: {url} ({len(html_content)} bytes)")
                            else:
                                logger.warning(f"바디 URL에서 받아올 데이터가 없음: {url}")
                                
                                # Fragment URL인 경우 기본 URL로 다시 시도
                                if '#' in url:
                                    base_url = url.split('#')[0]
                                    if base_url not in [existing_url.split('#')[0] for existing_url in body_html_contents.keys()]:
                                        logger.info(f"Trying base URL without fragment: {base_url}")
                                        try:
                                            base_html_content = await self.fetch_url_html(base_url)
                                            if base_html_content:
                                                body_html_contents[base_url] = base_html_content
                                                successful_body_urls += 1
                                                logger.info(f"base URL에서 html 가져오기 성공: {base_url} ({len(base_html_content)} bytes)")
                                            else:
                                                logger.warning(f"HTML content가 base URL에도 없음: {base_url}")
                                        except Exception as base_e:
                                            logger.error(f"base URL 가져오기 살패 {base_url}: {str(base_e)}")
                        except Exception as e:
                            logger.error(f"바디 URL을 가져올 수 없음 {url}: {str(e)}")
                            
                            # Fragment URL인 경우에도 기본 URL로 시도
                            if '#' in url:
                                base_url = url.split('#')[0]
                                if base_url not in [existing_url.split('#')[0] for existing_url in body_html_contents.keys()]:
                                    logger.info(f"오류 발생, base URL로 시도: {base_url}")
                                    try:
                                        base_html_content = await self.fetch_url_html(base_url)
                                        if base_html_content:
                                            body_html_contents[base_url] = base_html_content
                                            successful_body_urls += 1
                                            logger.info(f"오류가 났지만 base url을 성공적으로 가져옴: {base_url}")
                                    except Exception as base_e:
                                        logger.error(f"Base URL도 실패함 {base_url}: {str(base_e)}")
                                        
                official_html_contents = {}
                if 'brand_analysis' in initial_analysis:
                    official_sites = initial_analysis.get('brand_analysis', {}).get('official_sites', {})
                    
                    # 이메일 본문에서 문맥 추출
                    email_body = email_data.get('body', '')
                    email_subject = email_data.get('subject', '')
                    context_text = (email_subject + ' ' + email_body).lower()
                    
                    logger.info(f"공식 사이트 HTML 수집 시작: {len(official_sites)}개 브랜드")
                    
                    for brand, urls in official_sites.items():
                        # 문맥 기반 URL 선택 로직
                        selected_url = None
                        
                        # 1. 문맥 키워드 기반 필터링
                        context_patterns = {
                            # 택배/배송 관련
                            r'(택배|배송|배달|패키지|물품|상품|운송)': [
                                # 범용 물류 도메인 패턴
                                r'\b[\w-]*(logistic|express|delivery|parcel|courier|shipping|transport|cargo|freight)[\w-]*\.(com|co\.kr|net|org)(?:/[\w-]*)?$',
                                
                                # 추적 서비스 패턴  
                                r'\b(track|trace|ship)\.[\w-]+\.(com|co\.kr|net)(?:/[\w-]*)?$',
                                
                                # 우체국 전용 패턴 (epost만)
                                r'\b(www\.|service\.|ems\.|biz\.|parcel\.)?epost\.go\.kr(?!/bank)(?:/[\w-]*)?$',
                                
                                # 기존 키워드 (하위 호환성)
                                r'parcel', r'delivery', r'택배', r'배송'
                            ],
                            # 금융/은행 관련
                            r'(은행|예금|대출|계좌|이체|송금|금융)': [
                                r'bank', r'금융', r'예금', r'대출', r'epostbank'
                            ],
                            # 과태료/벌금 관련
                            r'(과태료|벌금|범칙금|납부|고지서)': [
                                r'fine', r'efine', r'과태료', r'벌금'
                            ],
                            # 세금 관련
                            r'(세금|국세|지방세|소득세|부가세)': [
                                r'tax', r'hometax', r'세금', r'국세'
                            ],
                            # 민원/행정 관련
                            r'(민원|신청|발급|증명서|신고)': [
                                r'minwon', r'gov\.kr', r'민원', r'신청'
                            ],
                            r'(로그인|계정|인증|비밀번호|아이디|보안|인증번호|OTP)': [
                                # 포털
                                r'\b(www\.)?naver\.com(?:/.*)?$',
                                r'\b(www\.)?daum\.net(?:/.*)?$',
                                r'\b(www\.)?google\.(co\.kr|com)(?:/.*)?$',
                                
                                # SNS
                                r'\b(www\.)?instagram\.com(?:/.*)?$',
                                r'\b(www\.)?facebook\.com(?:/.*)?$',
                                r'\b(www\.)?x\.com(?:/.*)?$',
                                r'\b[\w-]*\.kakao\.com(?:/.*)?$',
                                
                                # 커뮤니티  
                                r'\b(www\.)?everytime\.kr(?:/.*)?$',
                                r'\b(www\.)?dcinside\.com(?:/.*)?$',
                                r'\b(www\.)?fmkorea\.com(?:/.*)?$',
                                r'\b(www\.)?theqoo\.net(?:/.*)?$',
                                r'\b(www\.)?clien\.net(?:/.*)?$',
                                
                                # 쇼핑몰
                                r'\b(www\.)?coupang\.com(?:/.*)?$',
                                r'\b(www\.)?gmarket\.co\.kr(?:/.*)?$',
                                r'\b(www\.)?11st\.co\.kr(?:/.*)?$',
                                
                                # 대학
                                r'\b[\w-]*\.(ac\.kr|edu)(?:/.*)?$',
                                
                                # 정부
                                r'\b[\w-]*\.go\.kr(?:/.*)?$',
                                
                                r'로그인', r'계정', r'비밀번호'
                            ],
                            
                            # 커뮤니티/게시판 관련
                            r'(커뮤니티|게시판|댓글|익명|토론|정보공유|게시물|포스팅)': [
                                # 전통적인 커뮤니티
                                r'\b(www\.)?dcinside\.com(?:/.*)?$',
                                r'\b(www\.)?fmkorea\.com(?:/.*)?$',
                                r'\b(www\.)?theqoo\.net(?:/.*)?$',
                                r'\b(www\.)?everytime\.kr(?:/.*)?$',
                                r'\b(www\.)?clien\.net(?:/.*)?$',
                                
                                # SNS (커뮤니티 기능 있음)
                                r'\b(www\.)?instagram\.com(?:/.*)?$',
                                r'\b(www\.)?facebook\.com(?:/.*)?$',
                                r'\b(www\.)?x\.com(?:/.*)?$',
                                
                                # 포털 커뮤니티
                                r'\b(cafe|blog)\.naver\.com(?:/.*)?$',
                                r'\b(cafe|blog)\.daum\.net(?:/.*)?$',
                                
                                r'커뮤니티', r'게시판', r'댓글'
                            ],
                            
                            # 쇼핑/주문 관련
                            r'(주문|결제|배송|쿠폰|할인|장바구니|상품|구매)': [
                                # 쇼핑몰들
                                r'\b(www\.)?coupang\.com(?:/.*)?$',
                                r'\b(www\.)?gmarket\.co\.kr(?:/.*)?$',
                                r'\b(www\.)?11st\.co\.kr(?:/.*)?$',
                                r'\b(www\.)?ssg\.com(?:/.*)?$',
                                
                                # 쇼핑 관련 패턴
                                r'\b(shop|mall|store)\.[\w-]+\.(com|co\.kr)(?:/.*)?$',
                                
                                r'쇼핑', r'주문', r'결제'
                            ]
                        }
                        
                        # 2. 문맥과 URL 매칭
                        best_score = 0
                        for url in urls:
                            score = 0
                            url_lower = url.lower()
                            
                            # 문맥 패턴 체크
                            for context_pattern, url_patterns in context_patterns.items():
                                if re.search(context_pattern, context_text):
                                    for url_pattern in url_patterns:
                                        if re.search(url_pattern, url_lower):
                                            score += 10
                                            logger.debug(f"URL {url}이 패턴 {url_pattern}과 매칭 (문맥: {context_pattern})")
                            
                            # 브랜드명 포함 체크
                            if brand.lower() in url_lower:
                                score += 5
                            
                            # 정부/공식 도메인 가중치
                            if re.search(r'\.(go\.kr|or\.kr|gov)(?:/|$)', url_lower):
                                score += 3
                            
                            # 최고 점수 URL 선택
                            if score > best_score:
                                best_score = score
                                selected_url = url
                        
                        # 3. 선택된 URL이 없으면 첫 번째 URL 사용 (폴백)
                        if not selected_url:
                            selected_url = urls[0]
                            logger.info(f"문맥 매칭 실패, 기본 URL 사용: {brand} - {selected_url}")
                        else:
                            logger.info(f"문맥 기반 URL 선택: {brand} - {selected_url} (점수: {best_score})")
                        
                        # 4. HTML 수집
                        try:
                            html = await self.fetch_url_html(selected_url)
                            if html:
                                official_html_contents[selected_url] = self.extract_html_features(html)
                                logger.info(f"공식 사이트 HTML 수집 성공: {selected_url}")
                        except Exception as e:
                            logger.error(f"공식 사이트 HTML 수집 실패: {selected_url} - {e}")
                
                
                
                # 디버깅 정보 출력
                logger.info(f"Header URLs 찾음: {len(header_urls)}, Valid: {len(valid_header_urls)}, Successfully fetched: {len(header_html_contents)}")
                logger.info(f"Body URLs 찾음: {len(body_urls)}, Successfully fetched: {len(body_html_contents)}")
                
                # HTML 비교 분석용 데이터 준비
                comparison_data = {
                    'header_urls': list(header_html_contents.keys()),
                    'body_urls': list(body_html_contents.keys()),
                    'header_html_samples': {},
                    'body_html_samples': {},
                    'original_header_urls': header_urls,
                    'original_body_urls': body_urls,
                    'official_sites_html': official_html_contents,
                    'original_header_urls': header_urls,
                    'original_body_urls': body_urls     
                }
                
                # HTML 샘플 추출 (각 500자)
                for url, html in header_html_contents.items():
                    comparison_data['header_html_samples'][url] = self.extract_html_features(html)
                
                for url, html in body_html_contents.items():
                    comparison_data['body_html_samples'][url] = self.extract_html_features(html)
                    
                
                
                # 1개 AI로 분석
                ai_tasks = []
                '''
                if self.openai_client:
                    ai_tasks.append(self.analyze_with_chatgpt(email_data, comparison_data))
                if PERPLEXITY_API_KEY:
                    ai_tasks.append(self.analyze_with_perplexity(email_data, comparison_data))
                if self.gemini_model:
                    ai_tasks.append(self.analyze_with_gemini(email_data, comparison_data))
                if self.xai_client:  
                    ai_tasks.append(self.analyze_with_grok(email_data, comparison_data))
                '''
                if self.anthropic_client:
                    ai_tasks.append(self.analyze_with_claude(email_data, comparison_data))

                
                logger.info(f"{len(ai_tasks)}개 AI 모델로 분석 시작")
                
                ai_results = await asyncio.gather(*ai_tasks, return_exceptions=True)
                ai_results = [r for r in ai_results if isinstance(r, dict) and r is not None]
                
                logger.info(f"{len(ai_results)}개 AI 모델 분석 완료")
                
                # url_comparison을 여기서 생성
                url_comparison = {
                    'similarity': 0.0,
                    'suspicious_differences': [],
                    'risk_score': 0.0
                }
                
                # 실제 HTML 내용 기반 비교
                if header_html_contents and body_html_contents:
                    # 도메인 신뢰도 체크
                    for body_url in body_html_contents.keys():
                        body_domain = urlparse(body_url).netloc
                        is_trusted = False
                        
                        for header_url in header_html_contents.keys():
                            header_domain = urlparse(header_url).netloc
                            if body_domain == header_domain:
                                is_trusted = True
                                break
                        
                        if not is_trusted:
                            url_comparison['suspicious_differences'].append(f"본문 URL 도메인 불일치: {body_domain}")
                            url_comparison['risk_score'] += 0.3
                
                return ai_results, url_comparison

            
            ai_results, url_comparison = loop.run_until_complete(run_analysis())
            loop.close()
            
            if not ai_results:
                logger.warning("AI 분석 결과가 없습니다.")
                return None
            
            # 통계적 결과 통합
            integrated_result = self.integrate_ai_results_with_statistics(ai_results, url_comparison)
            
            # 최종 결과
            ai_result = {
                "risk_score": integrated_result['risk_score'],
                "verdict": integrated_result['verdict'],
                "suspicious_elements": url_comparison.get('suspicious_differences', []),
                "explanation": integrated_result['explanation'],
                "recommendation": integrated_result['recommendation'],
                "ai_analysis_details": integrated_result['statistics']
            }
            
            # 결과 저장
            result_path = self.result_dir / "ai_analysis_result.json"
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(ai_result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"다중 AI 분석 완료: 위험도 {ai_result['risk_score']}/100, 판정: {ai_result['verdict']}")
            
            return ai_result
            
        except Exception as e:
            logger.error(f"다중 AI 분석 중 오류 발생: {e}")
            logger.error(traceback.format_exc())
            return {
                "risk_score": 0,
                "verdict": "분석 실패",
                "suspicious_elements": [],
                "explanation": f"AI 분석 중 오류 발생: {str(e)}",
                "recommendation": "기본 분석 결과를 참고하세요."
            }
    
    async def fetch_url_html(self, url: str, save_to_file: bool = True) -> str:
        """URL에서 HTML 내용 가져오기"""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as response:
                    if response.status == 200:
                        # 인코딩 문제 처리
                        try:
                            content = await response.text(encoding='utf-8')
                        except:
                            content = await response.read()
                            content = content.decode('utf-8', errors='ignore')
                        
                        logger.info(f"HTML 수집 성공: {url} ({len(content)} bytes)")
                        
                        # HTML 파일로 저장
                        if save_to_file:
                            # URL을 파일명으로 변환 (안전한 이름으로)
                            import hashlib
                            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
                            safe_filename = re.sub(r'[^\w\-_.]', '_', url.split('//')[-1])[:50]
                            filename = f"fetched_html_{safe_filename}_{url_hash}.html"
                            
                            html_save_path = self.result_dir / "fetched_htmls"
                            html_save_path.mkdir(exist_ok=True)
                            
                            file_path = html_save_path / filename
                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                            
                            logger.info(f"HTML 저장 완료: {file_path}")
                        
                        return content
        except Exception as e:
            logger.error(f"HTML 수집 실패 {url}: {e}")
        return ""
    
    def extract_html_features(self, html: str) -> Dict[str, Any]:
        """HTML에서 주요 특징 추출"""
        features = {
            'title': '',
            'forms': [],
            'links': [],
            'text_sample': '',
            'structure': ''
        }
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # 제목 추출
            title = soup.find('title')
            if title:
                features['title'] = title.text[:100]
            
            # 폼 분석
            forms = soup.find_all('form')
            for form in forms[:3]:
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', ''),
                    'inputs': []
                }
                inputs = form.find_all('input')
                for inp in inputs[:5]:
                    form_data['inputs'].append({
                        'type': inp.get('type', ''),
                        'name': inp.get('name', '')
                    })
                features['forms'].append(form_data)
            
            # 주요 링크 추출
            links = soup.find_all('a', href=True)
            for link in links[:10]:
                features['links'].append(link['href'])
            
            # 텍스트 샘플
            text = soup.get_text()
            text = ' '.join(text.split())
            features['text_sample'] = text[:500]
            
            # 구조 정보
            features['structure'] = f"forms: {len(forms)}, links: {len(links)}"
            
        except Exception as e:
            logger.error(f"HTML 특징 추출 오류: {e}")
        
        return features
    
    async def analyze_with_claude(self, email_data: Dict, comparison_data: Dict) -> Dict:
        """Claude로 분석"""
        if not self.anthropic_client:
            return None
            
        try:
            prompt = self.create_ai_prompt(email_data, comparison_data)
            
            response = self.anthropic_client.messages.create(
                model="claude-3-7-sonnet-20250219",
                max_tokens=4000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            
            result_text = response.content[0].text
            logger.info(f"Claude 응답 (길이: {len(result_text)}): {result_text[:4000]}...")
            
            # 응답 파싱 개선
            is_spam = any(phrase in result_text.upper() for phrase in ['PHISHING: YES', 'SPAM: YES'])
            
            confidence_match = re.search(r'CONFIDENCE:\s*([\d.]+)', result_text)
            confidence = float(confidence_match.group(1)) if confidence_match else (0.8 if is_spam else 0.2)
            
            reason_match = re.search(r'REASON:\s*(.+)', result_text, re.DOTALL)
            reason = reason_match.group(1).strip() if reason_match else result_text[:500]
            
            return {
                'model': 'claude',
                'is_spam': is_spam,
                'confidence': confidence,
                'reason': reason
            }
            
        except anthropic.RateLimitError as e:
            logger.warning(f"Claude API 한도 초과: {e}")
            return None
        except Exception as e:
            logger.error(f"Claude 분석 오류: {e}")
            return None

    def integrate_ai_results_with_statistics(self, ai_results: List[Dict], url_comparison: Dict) -> Dict:
        """AI 결과를 통계적으로 통합"""
        if not ai_results:
            return {
                'risk_score': 0,
                'verdict': '분석 실패',
                'confidence': 0.0,
                'explanation': 'AI 분석 결과가 없습니다.',
                'recommendation': '기본 분석 결과를 참고하세요.',
                'statistics': {}
            }
        
        # 디버깅을 위한 결과 출력
        logger.info("=== AI 분석 결과 집계 시작 ===")
        spam_votes = 0
        total_votes = len(ai_results)
        
        for i, result in enumerate(ai_results, 1):
            model = result.get('model', 'unknown')
            is_spam = result.get('is_spam', False)
            confidence = result.get('confidence', 0)
            
            if is_spam:
                spam_votes += 1
                
            logger.info(f"{i}. {model}: {'스팸' if is_spam else '정상'} (신뢰도: {confidence:.2f})")
        
        logger.info(f"집계 결과: 총 {total_votes}개, 스팸 {spam_votes}개, 정상 {total_votes - spam_votes}개")
        
        # 통계 계산
        confidences = [r['confidence'] for r in ai_results]
        avg_confidence = statistics.mean(confidences)
        median_confidence = statistics.median(confidences)
        
        if len(confidences) > 1:
            stdev_confidence = statistics.stdev(confidences)
        else:
            stdev_confidence = 0
        
        # 스팸 판정 (과반수 기준)
        spam_ratio = spam_votes / total_votes
        is_spam = spam_ratio > 0.5
        
        # 위험도 점수 계산
        if is_spam:
            risk_score = int(avg_confidence * 100)
        else:
            risk_score = int((1 - avg_confidence) * 30)
        
        # 결과 설명
        explanation = (
            f"AI {total_votes}개 모델 분석 결과: "
            f"스팸 {spam_votes}개, 정상 {total_votes - spam_votes}개 | "
            f"평균 신뢰도: {avg_confidence:.2f}"
        )
        
        logger.info(f"최종 AI 판정: {'스팸' if is_spam else '정상'}, 위험도: {risk_score}")
        
        return {
            'risk_score': risk_score,
            'verdict': '위험' if is_spam else '안전',
            'confidence': avg_confidence,
            'explanation': explanation,
            'recommendation': '스팸함으로 이동하거나 삭제하세요.' if is_spam else '안전한 이메일입니다.',
            'statistics': {
                'models_used': [r['model'] for r in ai_results],
                'spam_votes': spam_votes,
                'total_votes': total_votes,
                'spam_ratio': spam_ratio,
                'average_confidence': avg_confidence,
                'median_confidence': median_confidence,
                'stdev_confidence': stdev_confidence
            }
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
            
            # 세션 ID 생성
            self.session_id = self.result_dir.name
            logger.info(f"출력 디렉토리 생성: {self.result_dir}")
            logger.info(f"첨부 파일 디렉토리 생성: {self.attachments_dir}")
            
            with open(email_path, 'rb') as f:
                raw_email = f.read()
                
            logger.info(f"이메일 파일 '{email_path}' 읽는 중...")
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            # 현재 메시지 저장 (헤더 추출용)
            self.current_msg = msg
            
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
                'from': from_header,
                'body': body,
                'attachments': attachments,
                'raw_email': raw_email
            }
            
        except Exception as e:
            logger.error(f"이메일 파싱 오류: {e}")
            raise
    
    def get_email_body(self, msg):
        """이메일 본문 추출 (HTML 우선, 중첩된 멀티파트 지원)"""
        body = ""
        
        # 모든 파트를 순회하며 HTML/텍스트 찾기
        html_found = False
        text_body = ""
        
        if msg.is_multipart():
            # msg.walk()로 모든 중첩된 파트 순회
            for part in msg.walk():
                content_type = part.get_content_type()
                
                if content_type == 'text/html' and not html_found:
                    try:
                        body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                        html_found = True
                        return body  # HTML을 찾았으면 즉시 반환
                    except Exception as e:
                        logger.warning(f"HTML 본문 디코딩 실패: {e}")
                        continue
                
                elif content_type == 'text/plain' and not text_body:
                    try:
                        text_body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                    except Exception as e:
                        logger.warning(f"텍스트 본문 디코딩 실패: {e}")
                        continue
        else:
            # 단일 파트 메시지
            content_type = msg.get_content_type()
            if content_type == 'text/html':
                try:
                    body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                    return body
                except Exception as e:
                    logger.warning(f"HTML 본문 디코딩 실패: {e}")
            elif content_type == 'text/plain':
                try:
                    text_body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                except Exception as e:
                    logger.warning(f"텍스트 본문 디코딩 실패: {e}")
        
        # HTML이 없으면 텍스트를 HTML로 변환
        if text_body:
            body = f"<html><head><meta charset='utf-8'></head><body><pre>{text_body}</pre></body></html>"
        
        return body
    
    def extract_text_from_html(self, html):
        """HTML에서 텍스트 추출 - 개선된 버전"""
        try:
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
                all_texts = [t for t in all_texts if len(t) > 3]
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
        """이메일 분석 메인 함수"""
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
            
            # 현재 이메일 제목 저장
            self.current_email_subject = parsed_data.get('subject', '')
            
            # 2. 헤더 분석
            header_result = self.header_analyzer.analyze_email(parsed_data['raw_email'])
            
            # 3. 헤더 직접 검사
            msg = parsed_data['msg']
            
            # 헤더 인증 값 확인
            spf_header = msg.get('Received-SPF', '')
            dkim_header = msg.get('DKIM-Signature', '')
            dmarc_header = msg.get('DMARC-Result', '')
            
            # 구글 서비스 이메일 특화 헤더 확인
            is_google_service = False
            from_header = parsed_data['msg'].get('From', '')
            google_dkim = msg.get('X-Google-DKIM-Signature', '')
            
            if ('google.com' in from_header.lower() and google_dkim) or \
               ('noreply@google.com' in from_header.lower()) or \
               ('forms-receipts-noreply@google.com' in from_header.lower()):
                is_google_service = True
                logger.info("Google 서비스 이메일로 감지됨")
            
            # SPF, DKIM, DMARC 검증
            if spf_header and 'pass' in spf_header.lower():
                header_result['spf_check'] = 'pass'
            else:
                header_result['spf_check'] = 'unknown'
                if is_google_service:
                    header_result['spf_check'] = 'pass'

            if dkim_header:
                header_result['dkim_check'] = 'pass'
            else:
                header_result['dkim_check'] = 'unknown'
                if is_google_service and google_dkim:
                    header_result['dkim_check'] = 'pass'

            if dmarc_header and 'pass' in dmarc_header.lower():
                header_result['dmarc_check'] = 'pass'
            else:
                header_result['dmarc_check'] = 'unknown'
                if is_google_service:
                    header_result['dmarc_check'] = 'none'
            
            # 4. 본문 분석
            html_body = parsed_data['body']
            text_body = self.extract_text_from_html(html_body)
            
            logger.info(f"총 추출된 내용 길이: {len(text_body)} 자")
            
            # 조직 유형 정보 추출
            org_type = header_result.get('organization_type', 'unknown')
            org_subtype = header_result.get('organization_subtype', 'unknown')
            
            # 본문 분석
            body_result = self.body_analyzer.analyze_text(text_body, org_type, org_subtype)
            
            # URL 분석 결과 추출
            url_analysis = body_result.get('url_analysis', {})
            
            # 5. 브랜드 매칭 분석 (NLP 기반)
            brand_analysis = {}
            if hasattr(self, 'spacy_nlp') or True:  # NLP 사용 가능한 경우
                email_data_for_brand = {
                    'subject': parsed_data.get('subject', ''),
                    'body': text_body,
                    'from': parsed_data.get('from', '')
                }
                
                # 비동기 실행
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    brand_analysis = loop.run_until_complete(
                        self.analyze_brand_matching(email_data_for_brand)
                    )
                    logger.info(f"브랜드 분석 완료: {brand_analysis.get('extracted_brands', [])}")
                except Exception as e:
                    logger.error(f"브랜드 분석 중 오류: {e}")
                    brand_analysis = {
                        'extracted_brands': [],
                    }
                finally:
                    loop.close()
            
            # 6. 첨부 파일
            attachments = parsed_data['attachments']
            
            # 7. 위험도 계산
            risk_score = 0
            risk_threshold = 70
            reasons = []
            
            # SPF/DKIM/DMARC 검증 실패 시
            if header_result.get('spf_check') not in ['pass', 'match']:
                risk_score += 15
                reasons.append("SPF 검증 실패: +15")
            
            if header_result.get('dkim_check') not in ['pass', 'none']:
                risk_score += 15
                reasons.append("DKIM 검증 실패: +15")
            
            if header_result.get('dmarc_check') not in ['pass', 'none']:
                risk_score += 5
                reasons.append("DMARC 검증 실패: +5")
            
            # 도메인 평판
            if header_result.get('domain_reputation') == 'suspicious':
                risk_score += 25
                reasons.append("도메인 평판 의심: +25")
            
            # 본문 키워드
            if body_result['total_matches'] > 0:
                for category, info in body_result['categories'].items():
                    if info['count'] > 0:
                        category_score = min(info['count'] * 5, 20)
                        risk_score += category_score
                        reasons.append(f"{category} 키워드 {info['count']}개: +{category_score}")
            
            # URL 위험도
            if url_analysis.get('risk_score', 0) > 0:
                url_risk = min(url_analysis['risk_score'], 30)
                risk_score += url_risk
                reasons.append(f"의심스러운 URL: +{url_risk}")
            
            if brand_analysis.get('typosquatting_detected'):
                risk_score += 10
                reasons.append("타이포스쿼팅 탐지: +10")
                
            if brand_analysis.get('suspicious_domains'):
                for susp_domain in brand_analysis['suspicious_domains']:
                    logger.warning(f"의심 도메인: {susp_domain.get('url', 'unknown')}")
            
            # 최종 위험도 제한
            risk_score = min(risk_score, 100)
            
            # 판정
            verdict = 'legitimate'
            if risk_score >= risk_threshold:
                verdict = 'dangerous'
            elif risk_score >= 25:
                verdict = 'suspicious'
            
            logger.info(f"최종 위험도 점수: {risk_score}/{risk_threshold}, 판정: {verdict}")
            
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
                'reasons': reasons,
                'subject': parsed_data.get('subject', ''),
                'metadata': metadata,
                'is_google_service': is_google_service,
                'url_analysis': url_analysis,
                'brand_analysis': brand_analysis  # 브랜드 분석 결과 추가
            }
            
            # 결과 JSON 파일로 저장
            result_path = self.result_dir / "analysis_result.json"
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"분석 결과 저장: {result_path}")
            
            # 8. AI 분석 수행 (다중 AI 사용)
            if AI_ENABLED and (ANTHROPIC_AVAILABLE or OPENAI_AVAILABLE or PERPLEXITY_API_KEY or GEMINI_AVAILABLE or XAI_AVAILABLE):
                email_data = {
                    'subject': parsed_data.get('subject', ''),
                    'from': parsed_data.get('from', ''),
                    'body': text_body,
                    'attachments': attachments
                }
                
                # 다중 AI 분석 호출
                ai_result = self.analyze_with_multi_ai(email_data, result)
                if ai_result:
                    # AI 분석 결과 추가
                    result['ai_analysis'] = ai_result
                    
                    # 최종 위험도 조정 (가중 평균)
                    ai_risk_score = ai_result.get('risk_score', 0)
                    if ai_risk_score > 0:
                        original_score = result['risk_score']
                        # 가중 평균 계산 (기본 분석 30%, AI 분석 70%)
                        adjusted_score = (original_score * 0.3) + (ai_risk_score * 0.7)
                        result['risk_score'] = round(adjusted_score)
                        result['ai_adjusted'] = True
                        logger.info(f"위험도 점수 조정: {original_score} → {result['risk_score']} (AI 평가: {ai_risk_score})")
                        
                        # 판정 재조정
                        if result['risk_score'] >= risk_threshold:
                            result['verdict'] = 'dangerous'
                        elif result['risk_score'] >= 25:
                            result['verdict'] = 'suspicious'
                        else:
                            result['verdict'] = 'legitimate'
                    
                    # AI 분석 결과도 저장
                    ai_result_path = self.result_dir / "ai_analysis_result.json"
                    with open(ai_result_path, 'w', encoding='utf-8') as f:
                        json.dump(ai_result, f, ensure_ascii=False, indent=2)
                    logger.info(f"AI 분석 결과 저장: {ai_result_path}")
            
            # 최종 결과 저장 (AI 분석 포함)
            final_result_path = self.result_dir / "final_analysis_result.json"
            with open(final_result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            logger.info("=== 이메일 분석 완료 ===")
            logger.info(f"최종 판정: {result['verdict']}")
            logger.info(f"최종 위험도: {result['risk_score']}/100")
            if brand_analysis.get('extracted_brands'):
                logger.info(f"추출된 브랜드: {', '.join(brand_analysis['extracted_brands'])}")
            
            return result
            
        except Exception as e:
            logger.error(f"이메일 분석 중 오류 발생: {e}")
            logger.error(traceback.format_exc())
            
            return {
                'verdict': 'error',
                'risk_score': 0,
                'risk_threshold': 70,
                'body': {'total_matches': 0, 'categories': {}},
                'header': {'final_verdict': 'error'},
                'session_path': self.session_id if hasattr(self, 'session_id') else 'unknown',
                'error': str(e),
                'brand_analysis': {}
            }
            
            
if __name__ == "__main__":
    print("=== 통합 피싱 탐지 시스템 학습 ===")
    
    kb = PhishingKnowledgeBase()
    
    # 기존 데이터 백업
    import shutil
    if os.path.exists("phishing_knowledge_base.pkl"):
        shutil.copy("phishing_knowledge_base.pkl", "phishing_knowledge_base_backup.pkl")
        print("기존 데이터 백업 완료")
    
    print("통합 학습 시작...")
    
    # 1. Zenodo 데이터셋 다운로드 및 학습
    kb.download_and_learn_zenodo()
    
    # 2. 한국 데이터셋 추가 학습
    korean_phishing, korean_normal = kb.download_and_learn_korean_dataset()
    
    # 3. 기존 Zenodo 데이터 다시 로드 (이미 학습됨)
    all_phishing = []
    all_normal = []
    
    # Zenodo 데이터 재로드
    dataset_files = [
        "CEAS_08.csv", "Enron.csv", "Ling.csv",
        "Nazario.csv", "Nazario_5.csv", "Nigerian_5.csv", 
        "SpamAssassin.csv", "Nigerian_Fraud.csv", 
        "TREC_05.csv", "TREC_06.csv", "TREC_07.csv"
    ]
    
    for file in dataset_files:
        file_path = f"zenodo_datasets/{file}"
        if os.path.exists(file_path):
            try:
                df = pd.read_csv(file_path, engine='python', encoding='utf-8', on_bad_lines='skip')
                df.columns = df.columns.str.lower().str.strip()
                
                # 데이터 추출 (기존 코드 재사용)
                label_col = None
                text_col = None
                
                for col in ['label', 'spam', 'class']:
                    if col in df.columns:
                        label_col = col
                        break
                
                for col in ['text', 'body', 'content']:
                    if col in df.columns:
                        text_col = col
                        break
                
                if label_col and text_col:
                    df = df.dropna(subset=[label_col, text_col])
                    phishing = df[df[label_col] == 1][text_col].tolist()
                    normal = df[df[label_col] == 0][text_col].tolist()
                    all_phishing.extend(phishing)
                    all_normal.extend(normal)
            except:
                continue
    
    # 4. 한국 데이터 추가
    all_phishing.extend(korean_phishing)
    all_normal.extend(korean_normal)
    
    print(f"통합 데이터: 피싱 {len(all_phishing)}개, 정상 {len(all_normal)}개")
    
    # 5. 통합 재학습
    kb.learn_patterns(all_phishing, all_normal)
    
    # 6. 통계 업데이트
    kb.statistics = {
        'total_samples': len(all_phishing) + len(all_normal),
        'phishing_samples': len(all_phishing),
        'normal_samples': len(all_normal),
        'zenodo_phishing': 102371,
        'zenodo_normal': 109338,
        'korean_phishing': len(korean_phishing),
        'korean_normal': len(korean_normal),
        'phishing_ratio': len(all_phishing) / (len(all_phishing) + len(all_normal) + 0.001)
    }
    
    kb.trained_date = datetime.now().isoformat()
    
    # 7. 저장
    kb.save("phishing_knowledge_base.pkl")
    
    print("\n=== 학습 완료 ===")
    print(f"Zenodo 데이터: 211,709개")
    print(f"한국 데이터: {len(korean_phishing) + len(korean_normal)}개")
    print(f"  - 피싱: {len(korean_phishing)}개")
    print(f"  - 정상: {len(korean_normal)}개")
    print(f"총 데이터: {kb.statistics['total_samples']}개")
    print(f"피싱 비율: {kb.statistics['phishing_ratio']:.2%}")