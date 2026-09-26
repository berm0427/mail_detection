# 외국어 번역 및 통합 판정 수동 확인용 EML

언어별 번역 경로 확인 파일 6개가 있습니다. 각 파일의 `엔진별 근거`에서 `문맥 입력: <언어 코드> → 한국어 로컬 번역`이 표시되는지 확인합니다.

- `english_suspicious.eml`: 영어 (`en`)
- `german_suspicious.eml`: 독일어 (`de`)
- `french_suspicious.eml`: 프랑스어 (`fr`)
- `spanish_suspicious.eml`: 스페인어 (`es`)
- `japanese_suspicious.eml`: 일본어 (`ja`)
- `arabic_suspicious.eml`: 아랍어 (`ar`)

이 6개는 번역 실행 여부를 확인하는 최소 EML이며 전체 판정 검증용이 아닙니다.

## 통합 판정 파일

`translation_integration_ar.eml`은 아랍어 제목·본문의 한국어 번역, 본문 문맥 ML, HTML 표시 주소와 실제 목적지의 불일치 탐지, 통합 주의 판정을 한 번에 확인하는 안전한 실행 예제입니다. 모든 주소와 링크는 실제 접속 대상이 없는 `.example` 예약 도메인을 사용합니다.

GUI에서 파일을 분석한 다음 다음 내용을 확인합니다.

- `본문 문맥 ML`: `문맥 입력: ar → 한국어 로컬 번역`
- `HTML 링크 비교`: 표시 호스트 `accounts.example`과 목적지 `verify.example`의 불일치
- `통합 판정`: 문맥 위험 신호와 구조 증거가 일치한 `주의`

이 예제는 번역과 판정 파이프라인의 연결을 확인하며 실제 탐지 정확도를 입증하지 않습니다.
