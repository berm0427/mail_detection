# 수동 재학습 방법

프로젝트 루트에서 다음 BAT를 실행한다.

```powershell
.\EmailTesterRetrainer.bat "C:\path\to\dataset.zip"
```

ZIP은 정상·피싱 라벨과 train/validation/test 분할이 들어 있는 기존 10,000건 형식을 따라야 한다. BAT는 다음 순서로 실행한다.

1. ZIP 안전 검사와 EML 분리
2. 학습 manifest 생성
3. MiniLM 문맥 임베딩 생성 또는 캐시 사용
4. 시나리오 그룹 교차검증
5. 후보 문맥 모델 생성
6. 학습에 넣지 않은 독립 manifest 평가

현재 재학습기는 `--semantic-model`이 필수다. 구형 문자 해싱 및 구조 evidence 후보 모델은 제거했다. 독립 평가를 통과하기 전에는 후보 모델이 메인 GUI 설정을 자동으로 덮어쓰지 않는다.