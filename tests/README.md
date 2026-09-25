# 테스트 디렉터리

## 자동 회귀 테스트

`test_*.py` 파일은 코드 변경 뒤 반복 실행하는 자동 테스트다.

```powershell
C:\Python314\python.exe -m unittest discover -s tests -p "test_*.py"
```

## 수동·통합 검사

다음 파일은 실제 GUI, NLP 런타임 또는 장시간 통합 경로를 확인할 때 사용한다.

- `auth_evidence_synthetic_check.py`
- `gui_flow_check.py`
- `nlp_runtime_check.py`
- `real_analyzer_gui_integration.py`
- `run_reliability_suite.py`

이 파일들은 과거 검증 문서가 재실행 경로로 참조하므로 삭제하거나 이동하지 않는다.

## 사용자 시험 메일

`mail_body/body_data/email1.eml`부터 `email8.eml`까지는 모델 학습에 넣지 않는 독립 시험 자료다.
