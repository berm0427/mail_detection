# 핵심 수치 재현 기록

운영 모델 `dise-ml-verdict-v4`와 그 평가 수치를 현재 코드로 처음부터 다시 만들어 기록된 값과 비교한 결과다.

- **재현 일자:** 2026-11-14
- **코드:** 브랜치 `feat/retrain-with-real-mail`, 커밋 `5d14cb9`
- **결과:** 기록된 값과 모두 일치. 운영 모델의 계수와 절편도 차이 0.

## 비교 결과

기록된 값은 `models/ml-verdict-v4-nested-10fold.metrics.json`, 운영 모델은 `models/dise-ml-verdict-v4.json`이다.

| 항목 | 기록된 값 | 재현한 값 |
|---|---|---|
| 문맥 단독 정확도 | 0.9885 | 0.9885 |
| 문맥 단독 오탐 / 미탐 | 9 / 106 | 9 / 106 |
| 문맥 단독 AUC / PR-AUC | 0.9988718 / 0.9990363 | 같음 |
| ML 판정 정확도 | 0.9944 | 0.9944 |
| ML 판정 오탐 / 미탐 | 3 / 53 | 3 / 53 |
| ML 판정 AUC / PR-AUC | 0.99945088 / 0.9995552 | 같음 |
| 정확 McNemar p | 1.1067861037383775e-14 | 같음 |
| 시나리오 그룹 부트스트랩 95% 구간 | 0.000825 ~ 0.014141 | 같음 |
| 최종 모델 계수 최대 차이 | – | 0.0 |
| 최종 모델 절편 차이 | – | 0.0 |
| 학습되지 않은 특징 목록 | – | 같음 |

평가는 합성 10,000건·15개 시나리오 그룹에 대한 외부 10중·내부 5중 중첩 그룹 교차검증이며, 판정 기준은 0.5로 미리 고정했다.
이 수치는 합성 시나리오 그룹 교차검증 결과로만 해석한다(`DATA_SOURCES.md` 참조).

## 재현 절차

세 단계다. 모두 저장소 루트에서 실행한다.

```powershell
# 1. 운영 분석기로 학습 특징 추출 (네트워크·Razor·첨부파일 검사 끔, 라벨 헤더 제거)
python -B tools/extract_synthetic_evidence.py `
  mail_body/training_data/korean_synthetic_v1/training_manifest.jsonl `
  analysis_result/repro-v4/evidence.jsonl --mode offline

# 2. 임베딩 캐시 생성: tools/retrain_ml_verdict.py 의 build_embedding_cache()
#    (운영 문맥 엔진과 같은 텍스트를 임베딩한다)

# 3. 중첩 그룹 교차검증과 최종 모델 학습
python -B tools/train_ml_verdict.py `
  mail_body/training_data/korean_synthetic_v1/training_manifest.jsonl `
  analysis_result/repro-v4/evidence.jsonl analysis_result/repro-v4/embeddings.npz `
  --metrics analysis_result/repro-v4/metrics.json `
  --artifact analysis_result/repro-v4/verdict.json `
  --semantic-artifact analysis_result/repro-v4/semantic.json `
  --embedding-model <다국어 MiniLM 모델 폴더>
```

2026-11-14 재현에서는 세 단계를 묶은 일회용 스크립트로 실행했고 약 7분이 걸렸다.
난수 시드는 코드에 42로 고정되어 있다.

## 입력과 산출물의 SHA-256

| 파일 | SHA-256 | Git 포함 |
|---|---|---|
| `mail_body/training_data/korean_synthetic_v1/training_manifest.jsonl` | `03c73bf1f7d7fefb90373da4858f0efab6fe27015ccfeffdef1cb4c5d4357a47` | 포함 |
| 재현 시 추출한 증거 `analysis_result/repro-v4/evidence.jsonl` | `5355a631a35d22198fcf6b6f6a643443556790398e223b5bffdd2301127f2bea` | 제외 |
| 재현 시 만든 임베딩 `analysis_result/repro-v4/embeddings.npz` | `1100cdfca0a667b692d4067788f7d24039651913f5e82b374c707b3a13922919` | 제외 |
| 운영 모델이 기록한 증거 `analysis_result/ml-verdict-v4/evidence_manifest-v5.jsonl` | `9806ff3ee947…` (모델 파일의 `evidence_manifest_sha256`와 일치) | 제외 |
| `models/dise-ml-verdict-v4.json` | `486f5629d2f1713be17c60a84dcb4400df009e6e3281a0997a9131411576e99a` | 포함 |
| `models/dise-multilingual-semantic-v4.json` | `670d91861dde254cf14ca872dc8cb2af4c815685b99f8607050510069ef3f1a8` | 포함 |
| `models/ml-verdict-v4-nested-10fold.metrics.json` | `5faee7b547668d82fd4431822067a29ef0591593309c5ff20efeb0769c7b68f4` | 포함 |

- 재현 시 증거 파일의 해시가 운영 모델이 기록한 해시와 다른 이유: 현재 추출기는 행마다 메일 내용 해시(`eml_sha256`)와
  추출 방식(`extraction_mode`)을 더 기록한다. 특징 값은 같아서 수치와 모델 계수가 일치한다.
- `analysis_result/`는 `.gitignore` 대상이다. 위 "제외" 파일은 이 저장소만으로는 얻을 수 없고, 위 절차로 다시 만들어야 한다.
- 재현으로 만든 판정 모델 파일은 운영 모델 파일과 바이트가 같지는 않다. 운영 파일에는 승격 표시와 기록 항목이 더 있다. 계수와 절편은 같다.

## 임베딩 모델

문맥 모델은 저장소 밖의 로컬 폴더에 있는 다국어 MiniLM(`paraphrase-multilingual-MiniLM-L12-v2`)을 사용한다.
`models/dise-multilingual-semantic-v4.json`의 `embedding_model_path`에 절대 경로가 기록되어 있어, 다른 PC에서는 경로를 맞춰야 한다.

| 파일 | SHA-256 |
|---|---|
| `config.json` | `6300193cb75e01cf80c96decef7187dfb33094d97cc1490b7ead6ff134476e4e` |
| `modules.json` | `8f4b264b80206c830bebbdcae377e137925650a433b689343a63bdc9b3145460` |
| `model.safetensors` | `eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b` |

## 실행 환경

- Windows 11 (10.0.26200), CPU 실행
- CPython 3.11.16
- NumPy 1.26.4, SciPy 1.17.1, scikit-learn 1.9.1
- sentence-transformers 6.0.1, Transformers 5.17.0, PyTorch 2.14.0+cpu

## 확인하지 않은 것

- 다른 PC나 다른 라이브러리 버전에서의 재현.
- 실제 이메일 8건 결과의 재현. 네트워크와 공식 사이트 상태에 따라 달라질 수 있다.
- 2판 논문 초안의 연구용 결합 실험(`models/fusion-nested-10fold-v1.metrics.json`). 그 수치는 커밋 `3431db0`의 특징 정의로 계산한 것이며,
  현재 코드로 다시 돌리면 달라질 수 있다.

## 단위 테스트

```powershell
python -B -m unittest discover -s tests
```

2026-11-14 기준 94개 모두 통과.
