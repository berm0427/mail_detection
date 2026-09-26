# 외국어 번역 통합 판정 수동 확인용 EML

이 폴더의 6개 메일은 정확도 평가나 학습 자료가 아닙니다. 각 언어에서 로컬 한국어 번역, 본문 문맥 ML, HTML 표시 주소와 실제 목적지 불일치 탐지, 통합 주의 판정을 한 번에 확인하는 안전한 실행 예제입니다. 모든 주소와 링크는 실제 접속 대상이 없는 `.example` 예약 도메인을 사용합니다.

- `translation_integration_en.eml`: 영어
- `translation_integration_de.eml`: 독일어
- `translation_integration_fr.eml`: 프랑스어
- `translation_integration_es.eml`: 스페인어
- `translation_integration_ja.eml`: 일본어
- `translation_integration_ar.eml`: 아랍어

GUI에서 각 파일을 분석한 다음 다음 내용을 확인합니다.

- `본문 문맥 ML`: `문맥 입력: <언어 코드> → 한국어 로컬 번역`
- `HTML 링크 비교`: 표시 호스트 `accounts.example`과 목적지 `verify.example`의 불일치
- `통합 판정`: 문맥 위험 신호와 구조 증거가 일치한 `주의`

이 예제들은 번역과 판정 파이프라인의 연결을 확인하며 실제 탐지 정확도를 입증하지 않습니다.
