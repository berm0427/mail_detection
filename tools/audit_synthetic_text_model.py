"""Audit synthetic text-model shortcuts and explain independent examples."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

from email_analyzer.evidence_features import message_text


def hashed_parts(text: str, coefficients: list[float]) -> list[dict]:
    bins = len(coefficients)
    compact = " " + re.sub(r"\s+", " ", text) + " "
    raw = collections.Counter()
    signed_bucket = collections.Counter()
    for n in (3, 4, 5):
        for index in range(max(0, len(compact) - n + 1)):
            token = compact[index:index + n]
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8, person=b"DISEml01").digest()
            number = int.from_bytes(digest, "big")
            bucket = number % bins
            sign = 1.0 if number & (1 << 63) else -1.0
            raw[(token, bucket, sign)] += 1
            signed_bucket[bucket] += sign
    norm = math.sqrt(sum(value * value for value in signed_bucket.values())) or 1.0
    values = []
    for (token, bucket, sign), count in raw.items():
        contribution = count * sign / norm * float(coefficients[bucket])
        values.append({"text": token, "bucket": bucket, "contribution": contribution})
    values.sort(key=lambda item: abs(item["contribution"]), reverse=True)
    return values


def word_shingles(text: str, limit: int = 2000) -> set[str]:
    words = re.findall(r"[0-9A-Za-z가-힣_@.-]+", text.casefold())[:limit]
    result = set(words)
    for size in (2, 3):
        result.update(" ".join(words[i:i + size]) for i in range(max(0, len(words) - size + 1)))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path)
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("external_manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--max-label-separation", type=float, default=.50)
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))
    coefficients = model["text_coef"]

    train_base = args.training_manifest.resolve().parent
    document_frequency = {0: collections.Counter(), 1: collections.Counter()}
    label_documents = collections.Counter()
    for line in args.training_manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("split") != "train":
            continue
        label = int(row["label"]); label_documents[label] += 1
        eml = (train_base / row["eml"]).resolve()
        message = BytesParser(policy=policy.default).parsebytes(eml.read_bytes())
        document_frequency[label].update(word_shingles(message_text(message)))

    shortcuts = []
    for token in set(document_frequency[0]) | set(document_frequency[1]):
        normal = document_frequency[0][token]; phishing = document_frequency[1][token]
        total = normal + phishing
        if total < 40:
            continue
        normal_rate = normal / label_documents[0]
        phishing_rate = phishing / label_documents[1]
        separation = abs(phishing_rate - normal_rate)
        if separation < .05:
            continue
        shortcuts.append({"text": token, "normal_documents": normal, "phishing_documents": phishing,
                          "normal_rate": normal_rate, "phishing_rate": phishing_rate,
                          "separation": separation})
    shortcuts.sort(key=lambda item: (item["separation"], item["normal_documents"] + item["phishing_documents"]), reverse=True)

    external_base = args.external_manifest.resolve().parent
    explanations = []
    for line in args.external_manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line); eml = (external_base / row["eml"]).resolve()
        message = BytesParser(policy=policy.default).parsebytes(eml.read_bytes())
        parts = hashed_parts(message_text(message), coefficients)
        explanations.append({"eml": row["eml"], "label": row["label"],
                             "toward_phishing": [x for x in parts if x["contribution"] > 0][:15],
                             "toward_normal": [x for x in parts if x["contribution"] < 0][:15]})

    gate_violations = [item for item in shortcuts if item["separation"] > args.max_label_separation]
    report = {
        "model_id": model.get("model_id"), "training_documents": dict(label_documents),
        "high_separation_training_phrases": shortcuts[:100],
        "external_explanations": explanations,
        "dataset_gate": {"passed": not gate_violations,
                         "max_label_separation": args.max_label_separation,
                         "violation_count": len(gate_violations)},
        "interpretation": "High-separation phrases reveal generator style. Hashed-token contributions are local diagnostics and can share buckets with other text.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"model_id": report["model_id"], "training_documents": report["training_documents"],
                      "shortcut_count": len(shortcuts), "explained_external_messages": len(explanations),
                      "dataset_gate": report["dataset_gate"],
                      "output": str(args.output)}, ensure_ascii=False, indent=2))
    if gate_violations and not args.audit_only:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
