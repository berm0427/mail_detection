"""Evaluate a semantic model artifact on an independent manifest."""
from __future__ import annotations

import argparse
import json
import math
from email import policy
from email.parser import BytesParser
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, roc_auc_score
from sentence_transformers import SentenceTransformer

from email_analyzer.evidence_features import message_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path); parser.add_argument("manifest", type=Path)
    parser.add_argument("report", type=Path); parser.add_argument("--min-rows", type=int, default=100)
    args = parser.parse_args(); artifact = json.loads(args.model.read_text(encoding="utf-8"))
    base = args.manifest.resolve().parent
    rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    texts, labels = [], []
    for row in rows:
        path = Path(row["eml"]); path = path if path.is_absolute() else (base / path).resolve()
        texts.append(message_text(BytesParser(policy=policy.default).parsebytes(path.read_bytes())))
        labels.append(int(row["label"]))
    encoder = SentenceTransformer(artifact["embedding_model_path"], device="cpu")
    x = encoder.encode(texts, batch_size=32, convert_to_numpy=True, normalize_embeddings=True)
    mean=np.asarray(artifact["mean"]);scale=np.asarray(artifact["scale"]);coef=np.asarray(artifact["coef"])
    z=(x-mean)/scale @ coef + float(artifact["intercept"])
    p=np.where(z>=0,1/(1+np.exp(-np.minimum(z,700))),np.exp(np.maximum(z,-700))/(1+np.exp(np.maximum(z,-700))))
    y=np.asarray(labels);prediction=p>=float(artifact.get("decision_threshold",.5))
    tn,fp,fn,tp=confusion_matrix(y,prediction,labels=[0,1]).ravel()
    observed={"rows":len(rows),"auc":float(roc_auc_score(y,p)),"accuracy":float((prediction==y).mean()),
              "tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp),"fpr":float(fp/max(fp+tn,1)),
              "recall":float(tp/max(tp+fn,1))}
    passed=len(rows)>=args.min_rows and observed["auc"]>=.75 and observed["fpr"]<=.15 and observed["recall"]>=.65
    report={"model_id":artifact["model_id"],"promotion_allowed":passed,"observed":observed,
            "predictions":[{"eml":r["eml"],"label":int(r["label"]),"score":float(s),"prediction":int(q)} for r,s,q in zip(rows,p,prediction)],
            "limitations":"A small audit set can reject a model but cannot establish real-world performance."}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2))
    if not passed:raise SystemExit(2)


if __name__=="__main__":main()
