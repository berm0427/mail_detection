"""Group-CV character model trained on every supplied synthetic row."""
from __future__ import annotations

import argparse,hashlib,json
from email import policy
from email.parser import BytesParser
from pathlib import Path
import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.model_selection import GroupKFold
from email_analyzer.evidence_features import EvidenceFeatureExtractor,message_text,hashed_char_ngrams


def metrics(y,p):
    prediction=p>=.5;tn,fp,fn,tp=confusion_matrix(y,prediction,labels=[0,1]).ravel()
    return {'auc':float(roc_auc_score(y,p)),'accuracy':float((prediction==y).mean()),
            'fpr':float(fp/max(fp+tn,1)),'recall':float(tp/max(tp+fn,1))}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('manifest',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--model-id',default='dise-text-group-cv-v1');parser.add_argument('--text-bins',type=int,default=4096)
    parser.add_argument('--folds',type=int,default=5);args=parser.parse_args();base=args.manifest.resolve().parent
    rows=[json.loads(line) for line in args.manifest.read_text(encoding='utf-8').splitlines() if line.strip()]
    y=np.asarray([int(r['label']) for r in rows]);groups=np.asarray([str(r['group_id']) for r in rows])
    sparse=[]
    for row in rows:
        path=Path(row['eml']);path=path if path.is_absolute() else base/path
        message=BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        sparse.append(hashed_char_ngrams(message_text(message),args.text_bins))
    ri=[];ci=[];values=[]
    for i,features in enumerate(sparse):
        for col,value in features.items():ri.append(i);ci.append(col);values.append(value)
    matrix=csr_matrix((values,(ri,ci)),shape=(len(rows),args.text_bins))
    folds=list(GroupKFold(n_splits=args.folds).split(matrix,y,groups));trials=[];best=None
    for c_value in (.001,.003,.01,.03,.1,.3,1.0,3.0):
        fold_results=[]
        for fold,(train_index,holdout_index) in enumerate(folds):
            model=LogisticRegression(C=c_value,max_iter=3000,class_weight='balanced',random_state=42,solver='liblinear')
            model.fit(matrix[train_index],y[train_index]);p=model.predict_proba(matrix[holdout_index])[:,1]
            result=metrics(y[holdout_index],p);result.update({'fold':fold,'groups':sorted(set(groups[holdout_index]))});fold_results.append(result)
        aggregate={name:float(np.mean([r[name] for r in fold_results])) for name in ('auc','accuracy','fpr','recall')}
        aggregate['min_fold_auc']=float(min(r['auc'] for r in fold_results));aggregate['max_fold_fpr']=float(max(r['fpr'] for r in fold_results))
        trials.append({'regularization_c':c_value,'aggregate':aggregate,'folds':fold_results})
        key=(aggregate['auc'],aggregate['min_fold_auc'],-aggregate['fpr'],aggregate['recall'],-c_value)
        if best is None or key>best[0]:best=(key,c_value)
    selected_c=best[1];model=LogisticRegression(C=selected_c,max_iter=3000,class_weight='balanced',random_state=42,solver='liblinear')
    model.fit(matrix,y);extractor=EvidenceFeatureExtractor();n=len(extractor.FEATURE_NAMES)
    artifact={'model_id':args.model_id,'schema_version':extractor.SCHEMA_VERSION,'feature_names':list(extractor.FEATURE_NAMES),
              'text_bins':args.text_bins,'positive_class':'label_1','decision_threshold':.5,'mean':[0.0]*n,'scale':[1.0]*n,
              'evidence_coef':[0.0]*n,'text_coef':model.coef_[0].tolist(),'intercept':float(model.intercept_[0]),
              'training_parameters':{'regularization_c':selected_c,'text_bins':args.text_bins,'rows':len(rows),'group_cv_folds':args.folds},
              'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest()}
    report={'rows':len(rows),'groups':len(set(groups)),'folds':args.folds,'external_data_used':False,'selected_c':selected_c,'trials':trials}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(artifact,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    args.output.with_suffix('.metrics.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'rows':len(rows),'groups':len(set(groups)),'selected_c':selected_c,
                      'selected':next(t for t in trials if t['regularization_c']==selected_c)['aggregate']},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
