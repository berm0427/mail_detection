"""Add existing semantic-model scores to an evidence manifest in batches."""

from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
import json
import math
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_DLL_HANDLES = []


def prepare_torch_runtime():
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        torch_lib = Path(sys.prefix) / "Lib" / "site-packages" / "torch" / "lib"
        if torch_lib.is_dir():
            _DLL_HANDLES.append(os.add_dll_directory(str(torch_lib)))


def sigmoid(value):
    return 1 / (1 + math.exp(-value)) if value >= 0 else math.exp(value) / (1 + math.exp(value))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("model", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()
    prepare_torch_runtime()
    from email_analyzer.engines.semantic_ml import preload_semantic_encoder
    from email_analyzer.evidence_features import message_text
    import numpy as np

    artifact = json.loads(args.model.read_text(encoding="utf-8"))
    encoder = preload_semantic_encoder(args.model)
    rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    mean = np.asarray(artifact["mean"]); scale = np.asarray(artifact["scale"])
    coefficient = np.asarray(artifact["coef"]); intercept = float(artifact["intercept"])
    threshold = float(artifact.get("decision_threshold", 0.5))
    for start in range(0, len(rows), args.batch_size):
        batch = rows[start:start + args.batch_size]
        texts = []
        for row in batch:
            message = BytesParser(policy=policy.default).parsebytes(Path(row["eml"]).read_bytes())
            texts.append(message_text(message))
        vectors = encoder.encode(texts, batch_size=args.batch_size, convert_to_numpy=True,
                                 normalize_embeddings=True, show_progress_bar=False)
        logits = ((vectors - mean) / scale) @ coefficient + intercept
        for row, logit in zip(batch, logits):
            score = sigmoid(float(logit))
            analysis = row.setdefault("analysis", {})
            engines = analysis.setdefault("engine_results", {})
            engines["semantic_ml"] = {
                "status": "ok", "score": score,
                "details": {"model_id": artifact["model_id"],
                            "predicted_label": int(score >= threshold),
                            "decision_threshold": threshold},
            }
        print(f"{min(start + args.batch_size, len(rows))}/{len(rows)}", flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                                     for row in rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
