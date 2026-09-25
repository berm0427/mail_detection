"""Select semantic-model regularization by scenario-group CV, then fit all rows."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler


def metrics(y, p):
    prediction=p>=.5;tn,fp,fn,tp=confusion_matrix(y,prediction,labels=[0,1]).ravel()
    return {"auc":float(roc_auc_score(y,p)),"accuracy":float((prediction==y).mean()),
            "fpr":float(fp/max(fp+tn,1)),"recall":float(tp/max(tp+fn,1))}


def main():
    parser=argparse.ArgumentParser();parser.add_argument("manifest",type=Path)
    parser.add_argument("cache",type=Path);parser.add_argument("embedding_model",type=Path)
    parser.add_argument("output",type=Path);parser.add_argument("--model-id",default="dise-semantic-group-cv-v1")
    parser.add_argument("--folds",type=int,default=5);args=parser.parse_args()
    rows=[json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    x=np.load(args.cache,allow_pickle=False)["embeddings"]
    y=np.asarray([int(row["label"]) for row in rows]);groups=np.asarray([str(row["group_id"]) for row in rows])
    if len(x)!=len(rows) or set(y)!={0,1}:raise ValueError("invalid cached embeddings or labels")
    if len(set(groups))<args.folds:raise ValueError("not enough groups")
    grid=(.0003,.001,.003,.01,.03,.1,.3,1.0,3.0)
    trials=[];best=None
    folds=list(GroupKFold(n_splits=args.folds).split(x,y,groups))
    for c_value in grid:
        fold_results=[]
        for fold,(train_index,holdout_index) in enumerate(folds):
            scaler=StandardScaler().fit(x[train_index]);train_x=scaler.transform(x[train_index]);holdout_x=scaler.transform(x[holdout_index])
            model=LogisticRegression(C=c_value,max_iter=3000,class_weight="balanced",random_state=42,solver="liblinear")
            model.fit(train_x,y[train_index]);probability=model.predict_proba(holdout_x)[:,1]
            result=metrics(y[holdout_index],probability);result.update({"fold":fold,"rows":len(holdout_index),"groups":sorted(set(groups[holdout_index]))})
            fold_results.append(result)
        aggregate={name:float(np.mean([r[name] for r in fold_results])) for name in ("auc","accuracy","fpr","recall")}
        aggregate["min_fold_auc"]=float(min(r["auc"] for r in fold_results));aggregate["max_fold_fpr"]=float(max(r["fpr"] for r in fold_results))
        trial={"regularization_c":c_value,"aggregate":aggregate,"folds":fold_results};trials.append(trial)
        key=(aggregate["auc"],aggregate["min_fold_auc"],-aggregate["fpr"],aggregate["recall"],-c_value)
        if best is None or key>best[0]:best=(key,c_value)
    selected_c=best[1];scaler=StandardScaler().fit(x);transformed=scaler.transform(x)
    model=LogisticRegression(C=selected_c,max_iter=3000,class_weight="balanced",random_state=42,solver="liblinear")
    model.fit(transformed,y)
    digest=hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    artifact={"model_id":args.model_id,"schema_version":1,"positive_class":"label_1","embedding_dimensions":int(x.shape[1]),
              "embedding_normalized":True,"embedding_model_path":str(args.embedding_model.resolve()),"decision_threshold":.5,
              "mean":scaler.mean_.tolist(),"scale":scaler.scale_.tolist(),"coef":model.coef_[0].tolist(),
              "intercept":float(model.intercept_[0]),"regularization_c":selected_c,"manifest_sha256":digest,
              "training_rows":len(rows),"group_cv_folds":args.folds}
    report={"rows":len(rows),"groups":len(set(groups)),"folds":args.folds,"external_data_used":False,
            "trials":trials,"selected_c":selected_c,"selection_rule":"mean AUC, minimum fold AUC, FPR, recall, then stronger regularization"}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(artifact,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    args.output.with_suffix(".metrics.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"rows":len(rows),"groups":len(set(groups)),"selected_c":selected_c,
                      "selected":next(t for t in trials if t["regularization_c"]==selected_c)["aggregate"]},ensure_ascii=False,indent=2))


if __name__=="__main__":main()
