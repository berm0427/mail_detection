"""Export paper-ready tables, figures, and a concise interpretation report."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def write_csv(path, fieldnames, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def font(size, bold=False):
    windows = Path("C:/Windows/Fonts")
    candidates = ["malgunbd.ttf" if bold else "malgun.ttf", "arialbd.ttf" if bold else "arial.ttf"]
    for name in candidates:
        path = windows / name
        if path.is_file():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def bar_chart(path, title, rows, metric, label, color):
    width, height = 1500, 760
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    draw.text((55, 35), title, fill="#152238", font=font(34, True))
    left, right, top, bottom = 320, 1430, 120, 670
    draw.line((left, top, left, bottom), fill="#77808f", width=2)
    draw.line((left, bottom, right, bottom), fill="#77808f", width=2)
    for tick in range(0, 101, 20):
        x = left + (right - left) * tick / 100
        draw.line((x, top, x, bottom), fill="#e3e7ec", width=1)
        draw.text((x - 18, bottom + 14), str(tick), fill="#485362", font=font(18))
    gap = (bottom - top) / max(len(rows), 1)
    for index, row in enumerate(rows):
        y = top + gap * index + gap * 0.18
        value = float(row[metric]) * 100
        x2 = left + (right - left) * value / 100
        draw.rounded_rectangle((left, y, x2, y + gap * 0.58), radius=8, fill=color)
        draw.text((30, y + 4), str(row[label]), fill="#263445", font=font(21))
        draw.text((min(x2 + 12, right - 85), y + 4), f"{value:.2f}%", fill="#152238", font=font(20, True))
    image.save(path, dpi=(300, 300))


def load_real8(manifest):
    rows = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        result = json.loads(Path(item["analysis_result"]).read_text(encoding="utf-8"))
        semantic = (result.get("engine_results") or {}).get("semantic_ml") or {}
        learned = result.get("experimental_learned_fusion") or {}
        production = int(result.get("verdict") in {"suspicious", "dangerous"})
        label = int(item["label"])
        rows.append({
            "id": item["id"], "label": label,
            "production_prediction": production,
            "production_correct": int(production == label),
            "semantic_score": round(float(semantic.get("score") or 0), 6),
            "semantic_prediction": int(float(semantic.get("score") or 0) >= 0.5),
            "fusion_score": round(float(learned.get("score") or 0), 6),
            "fusion_prediction": int(learned.get("prediction") or 0),
            "fusion_correct": int(int(learned.get("prediction") or 0) == label),
        })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nested_metrics", type=Path)
    parser.add_argument("real8_manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    metrics = json.loads(args.nested_metrics.read_text(encoding="utf-8"))
    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    performance = []
    sources = {"semantic_only": metrics["semantic_only"], **metrics["models"]}
    names = {
        "semantic_only": "문맥 ML 단독", "structure_logistic": "구조 Logistic",
        "fusion_logistic": "문맥+구조 Logistic", "fusion_random_forest": "문맥+구조 Random Forest",
    }
    for key, value in sources.items():
        performance.append({"method": key, "display_name": names[key], **value})
    write_csv(output / "table1_performance.csv", list(performance[0]), performance)

    ablations = [{"condition": key, **value} for key, value in metrics["ablations"].items()]
    write_csv(output / "table2_ablation.csv", list(ablations[0]), ablations)
    dropout = [{"condition": key, **value} for key, value in metrics["engine_dropout"].items()]
    write_csv(output / "table3_engine_dropout.csv", list(dropout[0]), dropout)
    paired = []
    for method, value in metrics["paired_tests"].items():
        paired.append({"method": method, **value["mcnemar"],
                       "accuracy_delta": value["group_bootstrap"]["accuracy_delta"],
                       "ci95_low": value["group_bootstrap"]["ci95"][0],
                       "ci95_high": value["group_bootstrap"]["ci95"][1]})
    write_csv(output / "table4_statistical_tests.csv", list(paired[0]), paired)
    real8 = load_real8(args.real8_manifest.resolve())
    write_csv(output / "table5_real8_audit.csv", list(real8[0]), real8)

    bar_chart(output / "figure1_accuracy.png", "중첩 10중 그룹 교차검증 정확도",
              performance, "accuracy", "display_name", "#2d6cdf")
    recall_rows = [{**row, "metric_name": row["display_name"]} for row in performance]
    bar_chart(output / "figure2_recall.png", "중첩 10중 그룹 교차검증 재현율",
              recall_rows, "recall", "metric_name", "#e06c36")

    logistic = metrics["models"]["fusion_logistic"]
    semantic = metrics["semantic_only"]
    test = metrics["paired_tests"]["fusion_logistic"]
    real_correct = sum(row["fusion_correct"] for row in real8)
    report = f"""# 증거 결합 계층 실험 결과

## 실험 설계

- 합성 이메일 10,000건과 독립 시나리오 그룹 15개를 사용했다.
- 외부 10중 그룹 교차검증에서 시험 시나리오를 통째로 격리했다.
- 각 외부 학습 집합 안에서 5중 그룹 검증으로 문맥 모델의 규제값을 선택했다.
- 결합 모델의 학습 입력에는 내부 out-of-fold 문맥 예측만 사용했다.
- 사용자가 제공한 실제 이메일 8건은 학습과 모델 선택에 사용하지 않았다.

## 주요 결과

문맥 ML 단독 정확도는 {semantic['accuracy']:.4f}, 재현율은 {semantic['recall']:.4f}, 오탐률은 {semantic['fpr']:.4f}였다. Logistic 결합 정확도는 {logistic['accuracy']:.4f}, 재현율은 {logistic['recall']:.4f}, 오탐률은 {logistic['fpr']:.4f}였다. 결합은 미탐을 {semantic['fn']}건에서 {logistic['fn']}건으로 줄였고 오탐은 {semantic['fp']}건에서 {logistic['fp']}건으로 1건 증가시켰다.

짝지은 오류 비교에서 Logistic 결합만 맞힌 표본은 {test['mcnemar']['baseline_only_wrong']}건, 문맥 단독만 맞힌 표본은 {test['mcnemar']['candidate_only_wrong']}건이었다. 정확 McNemar 검정의 p 값은 {test['mcnemar']['exact_mcnemar_p']:.6f}였다. 시나리오 그룹 부트스트랩 정확도 차이의 95% 구간은 {test['group_bootstrap']['ci95'][0]:.6f}~{test['group_bootstrap']['ci95'][1]:.6f}였다.

## 제거 및 장애 실험 해석

- 문맥 신호를 제거하면 정확도가 {metrics['ablations']['without_semantic']['accuracy']:.4f}로 하락했다.
- 인증 신호를 제거하면 정확도가 {metrics['ablations']['without_authentication']['accuracy']:.4f}로 하락했다.
- 첨부파일과 HTML 신호 제거 결과가 변하지 않은 것은 현재 합성 데이터에 해당 위험 신호의 변이가 충분하지 않기 때문이다.
- 문맥 엔진 장애 시 재현율이 {metrics['engine_dropout']['semantic_engine_unavailable']['recall']:.4f}로 하락했다. 현재 결합 모델은 문맥 엔진에 크게 의존한다.
- 문맥과 구조 모델이 충돌한 {metrics['natural_conflict_subset']['n']}건에서 문맥 단독 정확도는 {metrics['natural_conflict_subset']['semantic_only']['accuracy']:.4f}, Logistic 결합 정확도는 {metrics['natural_conflict_subset']['fusion_logistic']['accuracy']:.4f}였다.

## 실제 이메일 감사

실제 이메일 8건에서 학습 결합 모델은 {real_correct}/8건을 맞혔다. 합성 교차검증의 개선이 실제 소표본에서는 재현되지 않았으므로 결합 모델을 운영 GUI 판정에 승격하지 않았다. 이 결과는 실제 환경 성능의 확정값이 아니라 외부 타당성 한계를 보여주는 사례 감사로 사용한다.

## 논문에서 주장 가능한 범위

현재 결과는 시나리오 그룹을 분리한 합성 데이터에서 Logistic 결합이 문맥 단독보다 작지만 일관된 개선을 보였다는 점을 지지한다. 실제 환경 일반화, 첨부파일·HTML 엔진의 독립 기여, 기관·언어별 성능은 입증되지 않았다. 따라서 논문의 기여는 완성된 상용 탐지기의 우월성이 아니라 불확실성과 엔진 가용성을 기록하는 다중 증거 결합 구조 및 누수 통제 평가 절차로 한정한다.
"""
    (output / "RESULTS_KO.md").write_text(report, encoding="utf-8")
    print(json.dumps({"output": str(output.resolve()), "files": sorted(p.name for p in output.iterdir())},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
