# DISE 코드 구조

## 실행 경로

`EmailTesterStart.bat` → `tools/Start-User-Test.ps1` → `tools/run_user_test_gui.py` → `main_gui.py`

`email_analyzer/integration.py`가 EML 파싱, 헤더·DNS, URL, 목적지 HTML, 공식 사이트 비교, 첨부파일 검사와 ML 결과를 하나의 분석 결과로 조립한다. `email_analyzer/decision.py`가 서로 다른 점수를 단순 합산하지 않고 관측된 증거를 결합한다. `email_analyzer/engine_view.py`가 GUI의 엔진별 근거 행을 만든다.

## 현재 ML

- `email_analyzer/engines/semantic_ml.py`: 제목·본문 문맥 모델
- `email_analyzer/engines/html_pair_ml.py`: 목적지와 공식 페이지 HTML 구조 쌍 모델
- `models/dise-semantic-synthetic-v2-groupcv.json`: 현재 문맥 모델
- `email_analyzer/text_translation.py`: 비한국어 제목·본문을 로컬에서 한국어로 정규화하는 선택 경로

비한국어 제목·본문은 로컬 `M2M100 418M` 번역 모델이 지원하는 경우 한국어로 변환한 뒤
현재 문맥 모델에 입력한다. URL·이메일 주소·헤더·HTML 속성·첨부파일은 번역하지 않는다.
번역이 불가능하면 문맥 ML만 건너뛰고 구조 엔진은 계속 실행한다. 로컬 모델은 저장소에
포함하지 않으며 `PrepareLanguageModels.bat`으로 준비한다.

2026-09-26 검증에서 6개 언어 번역과 실제 GUI 통합 7개 시나리오가 완료됐다. 별도로
재학습한 다국어 MiniLM 후보는 사용자 메일 1–8에서 5/8에 그쳐 운영 모델로 승격하지 않았다.
기존 운영 모델은 번역 경로 추가 후에도 사용자 메일 1–8에서 기존과 같은 6/8이었다.
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
