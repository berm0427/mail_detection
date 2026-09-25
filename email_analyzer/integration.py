from email_analyzer.pipeline import analyze_engines
# email_analyzer/integration.py
import os
from langdetect import detect
from typing import Set, Tuple
import logging
import json
import uuid
import traceback
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

logger = logging.getLogger(__name__)

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


class IntegratedAnalyzer:
    """통합 이메일 분석기"""
        
    def __init__(self, keywords_dir, result_dir=None, attachments_dir=None, runtime_options=None):
        self.runtime_options = dict(runtime_options or {})
        self.header_analyzer = EmailHeaderAnalyzer()
        self.body_analyzer = BodyAnalyzer()
        self.user_email_domains = self.header_analyzer.user_email_domains
        self.result_dir = Path(result_dir) if result_dir else Path("analysis_result")
        self.attachments_dir = Path(attachments_dir) if attachments_dir else self.result_dir / "attachments"
        
        # 결과 저장 디렉토리 생성
        os.makedirs(self.result_dir, exist_ok=True)
        os.makedirs(self.attachments_dir, exist_ok=True)
        
        # URL 캐시
        self.url_cache = {}
        
    
    
       
    
   
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
    
    
    def extract_urls_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """Registered reference candidates, never inferred from DNS or reachability."""
        from email_analyzer.reference_evidence import load_registry, matches
        from email_analyzer.link_evidence import hostname
        registry = load_registry(self.runtime_options.get('reference_registry_path'))
        sender = hostname(self.get_sender_domain(headers))
        orgs = {r['organization'] for r in registry['domains'] if r['role'] in ('official', 'delegated_sender') and matches(sender, r)}
        return sorted({'https://' + r['domain'] for r in registry['domains'] if r['role'] == 'official' and r['organization'] in orgs})

    
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
        if self.runtime_options.get('disable_network'):
            return []
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
        

    
    async def fetch_url_html(self, url: str, save_to_file: bool = True) -> str:
        """URL에서 HTML 내용 가져오기"""
        if self.runtime_options.get('disable_network'):
            return ""
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
            
            engine_results = analyze_engines(msg, self.runtime_options.get('engine_config_override'))

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

                    if self.runtime_options.get('disable_attachment_scan'):
                        scan = {'engine': 'microsoft_defender', 'status': 'disabled', 'safe': None,
                                'reason': 'runtime_options.disable_attachment_scan'}
                    else:
                        from email_analyzer.attachment_scanner import scan_attachment
                        scan = scan_attachment(
                            attachment_path,
                            executable=self.runtime_options.get('attachment_scanner_executable'),
                            timeout=int(self.runtime_options.get('attachment_scan_timeout', 90)),
                        )

                    # 첨부 파일 정보 저장
                    attachments.append({
                        'filename': filename,
                        'size': os.path.getsize(attachment_path),
                        'path': str(attachment_path.relative_to(self.result_dir.parent.parent)),
                        'content_type': part.get_content_type(),
                        'type': part.get_content_type(),
                        'safe': scan.get('safe'),
                        'reason': scan.get('reason'),
                        'malware_scan': scan,
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
                'engine_results': engine_results,
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
            
            # Do not convert sender-controllable/pass-like headers into verified pass.
            # score_rules() will distinguish explicit fail, missing information, and
            # lookup errors without assigning failure points for mere absence.
            
            # 4. 본문 분석
            html_body = parsed_data['body']
            text_body = self.extract_text_from_html(html_body)
            
            logger.info(f"총 추출된 내용 길이: {len(text_body)} 자")
            
            # 조직 유형 정보 추출
            org_type = header_result.get('organization_type', 'unknown')
            org_subtype = header_result.get('organization_subtype', 'unknown')
            
            # 본문 분석
            from email_analyzer.link_evidence import collect_href_urls
            body_result = self.body_analyzer.analyze_text(text_body, org_type, org_subtype, additional_urls=collect_href_urls(msg))
            
            # URL 분석 결과 추출
            url_analysis = body_result.get('url_analysis', {})
            from email_analyzer.page_structure import analyze_pages
            page_urls = [x['url'] for x in collect_href_urls(msg)]
            page_urls.extend(x['url'] for x in url_analysis.get('analyzed_urls', []) if 'body_text' in x['sources'])
            page_analysis = analyze_pages(page_urls, disabled=self.runtime_options.get('disable_network', False))

            
            # Legacy NLP brand-search path was retired. Objective domain and HTML
            # evidence is produced by reference_evidence/homepage_comparison.
            brand_analysis = {}

            # 6. 첨부 파일
            attachments = parsed_data['attachments']
            
            # Existing rule arithmetic is shared with the offline evaluator.
            from email_analyzer.legacy_rules import annotate_auth_evidence, score_rules
            from email_analyzer.link_evidence import inspect_html_links
            try:
                link_evidence = inspect_html_links(msg)
            except Exception as exc:
                link_evidence = {'status': 'error', 'error_type': type(exc).__name__}
            header_result = annotate_auth_evidence(header_result, msg)
            from email_analyzer.reference_evidence import analyze_references
            try:
                reference_evidence = analyze_references(msg, self.runtime_options.get('reference_registry_path'))
            except Exception as exc:
                reference_evidence = {'status': 'error', 'error_type': type(exc).__name__, 'template_status': 'error',
                                      'ml': {'status': 'not_applied', 'reason': '참조 분석 오류'}}
            from email_analyzer.homepage_comparison import compare_homepages
            try:
                homepage_comparison = compare_homepages(msg, page_analysis, link_evidence, brand_analysis,
                    self.runtime_options.get('reference_registry_path'), self.runtime_options.get('disable_network', False))
            except Exception as exc:
                homepage_comparison = {'status': 'basic_only', 'references': [], 'comparisons': [], 'reason': type(exc).__name__}
            rule_result = score_rules(header_result, body_result, url_analysis, brand_analysis, reference_evidence)
            risk_score = rule_result['risk_score']
            risk_threshold = rule_result['risk_threshold']
            verdict = rule_result['verdict']
            reasons = rule_result['reasons']

            logger.info(f"최종 위험도 점수: {risk_score}/100 (위험 기준 {risk_threshold}), 판정: {verdict}")
            
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
                'page_analysis': page_analysis,
                'homepage_comparison': homepage_comparison,
                'link_evidence': link_evidence,
                'reference_evidence': reference_evidence,
                'engine_results': parsed_data['engine_results'],
                'rule_result': rule_result,
                'optional_features': {
                    'network': 'disabled' if self.runtime_options.get('disable_network') else 'enabled',
                },
                'brand_analysis': brand_analysis  # 브랜드 분석 결과 추가
            }

            from email_analyzer.evidence_features import EvidenceFeatureExtractor
            from email_analyzer.pipeline import analyze_evidence_engine
            result['evidence_features'] = {
                'schema_version': EvidenceFeatureExtractor.SCHEMA_VERSION,
                'features': EvidenceFeatureExtractor().extract(result),
            }
            result['engine_results']['evidence_ml'] = analyze_evidence_engine(
                msg, result, self.runtime_options.get('engine_config_override'))
            from email_analyzer.pipeline import analyze_semantic_engine
            result['engine_results']['semantic_ml'] = analyze_semantic_engine(
                msg, self.runtime_options.get('engine_config_override'))
            
            # 결과 JSON 파일로 저장
            result_path = self.result_dir / "analysis_result.json"
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            logger.info(f"분석 결과 저장: {result_path}")
            
            # 8. AI 분석 수행 (다중 AI 사용)
            
            from email_analyzer.decision import combine_evidence
            result['decision'] = combine_evidence(result)
            result['verdict'] = result['decision']['verdict']

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
            
            
