# 사용자 인수 테스트용 합성 EML 세트

이 디렉터리의 파일은 실제 개인 메일이 아닌 합성 입력이다.

| 파일 | 목적 | GUI 예상 결과 |
|---|---|---|
| `user_acceptance_legitimate_notice.eml` | 정상 회의 안내 형태 | 위험 신호가 낮게 표시되거나 인증 정보 부족 때문에 판정 유보가 될 수 있다. 미실행/미설치 엔진을 안전 근거로 해석하지 않는다. |
| `user_acceptance_missing_auth.eml` | 인증 정보 부재 구분 | `판정 유보`와 인증 정보 부족/검토 필요 근거가 표시되어야 한다. |
| `user_acceptance_forged_pass.eml` | 발신자 삽입 `Authentication-Results` 신뢰 방지 | 원문 삽입 인증값을 검증된 안전 근거로 확정하지 않아야 한다. |
| `user_acceptance_phishing_like.eml` | 키워드/URL 기반 피싱 유사 흐름 | 의심 또는 위험 신호와 본문 키워드/URL 근거가 표시되어야 한다. |
| `user_acceptance_konlpy_payload.eml` | KoNLPy 입력 데이터/코드 분리 | 따옴표, 삼중 따옴표, 역슬래시, 개행, 코드처럼 보이는 문자열이 실행되지 않고 데이터로 처리되어야 한다. |

결과 판정은 로컬 엔진 설치 상태와 인증 헤더 부재에 따라 `판정 유보`가 될 수 있다. 이 경우에도 GUI의 엔진별 근거와 `optional_features.nlp.konlpy` 상태가 실제 기능 상태를 반영하면 정상이다.
