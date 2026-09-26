# DISE 코드 구조

## 실행 경로

`EmailTesterStart.bat` → `tools/Start-User-Test.ps1` → `tools/run_user_test_gui.py` → `main_gui.py`

`email_analyzer/integration.py`가 EML 파싱, 헤더·DNS, URL, 목적지 HTML, 공식 사이트 비교, 첨부파일 검사와 ML 결과를 하나의 분석 결과로 조립한다. `email_analyzer/decision.py`가 서로 다른 점수를 단순 합산하지 않고 관측된 증거를 결합한다. `email_analyzer/engine_view.py`가 GUI의 엔진별 근거 행을 만든다.

## 현재 ML

- `email_analyzer/engines/semantic_ml.py`: 제목·본문 문맥 모델
- `email_analyzer/engines/html_pair_ml.py`: 목적지와 공식 페이지 HTML 구조 쌍 모델
- `models/dise-semantic-synthetic-v2-groupcv.json`: 현재 문맥 모델
- `models/dise-html-pair-phishpedia-v1.json`: 현재 HTML pair 모델

구형 문자 해싱·구조 evidence 모델과 manifest 이관 파이프라인은 사용하지 않아 제거했다.

## 객관 증거

- `legacy_rules.py`: 기존 규칙과 인증 관측 경계
- `page_structure.py`: 목적지 HTML 정적 구조 수집
- `homepage_comparison.py`, `official_site_discovery.py`: 공식 후보 탐색과 비교
- `link_evidence.py`, `reference_evidence.py`: URL·도메인 관계
- `attachment_scanner.py`: 자체 정적 검사, ClamAV, Defender

## 재학습

`EmailTesterRetrainer.bat`은 `tools/retrain_from_dataset_zip.py`를 호출한다. 재학습기는 MiniLM 임베딩, 시나리오 그룹 교차검증, 독립 메일 평가를 순서대로 실행한다. 문자 해싱 fallback은 없다.

## 테스트

- 전체 자동 테스트: `python -B -m unittest discover -s tests -v`
- GUI 통합 테스트: `python -B tests/run_reliability_suite.py`