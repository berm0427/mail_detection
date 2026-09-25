"""Train a gated hybrid model from pre-analyzed, independently split messages.

JSONL fields: eml, analysis_result, label (0/1), split
(train/validation/test), group_id. Paths are resolved relative to the manifest.
"""
import argparse,csv,hashlib,json
from email import policy
from email.parser import BytesParser
from pathlib import Path
import numpy as np
from scipy.sparse import csr_matrix,hstack
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.preprocessing import StandardScaler
from email_analyzer.evidence_features import EvidenceFeatureExtractor,message_text,hashed_char_ngrams


def metrics(y,p,threshold=.5):
    tn,fp,fn,tp=confusion_matrix(y,p>=threshold,labels=[0,1]).ravel()
    return {'n':int(len(y)),'auc':float(roc_auc_score(y,p)),'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp),
            'fpr':float(fp/max(fp+tn,1)),'recall':float(tp/max(tp+fn,1))}


def main():
    parser=argparse.ArgumentParser(description='Train gated text + objective evidence model')
    parser.add_argument('manifest',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--min-validation-auc',type=float,default=.75)
    parser.add_argument('--max-validation-fpr',type=float,default=.15)
    parser.add_argument('--min-validation-recall',type=float,default=.65)
    parser.add_argument('--text-bins',type=int,default=2048)
    parser.add_argument('--objective-only',action='store_true',help='train without message-text n-grams')
    parser.add_argument('--model-id',default='dise-hybrid-evidence-v1')
    parser.add_argument('--regularization-c',type=float,default=1.0)
    args=parser.parse_args();base=args.manifest.resolve().parent
    if args.regularization_c <= 0: parser.error('--regularization-c must be positive')
    rows=[]
    for line_no,line in enumerate(args.manifest.read_text(encoding='utf-8').splitlines(),1):
        if not line.strip():continue
        row=json.loads(line);row['_line']=line_no
        if row.get('split') not in ('train','validation','test') or row.get('label') not in (0,1) or not row.get('group_id'):
            raise ValueError(f'invalid manifest row {line_no}')
        rows.append(row)
    if len(rows)<30:raise ValueError('at least 30 rows are required')
    for split in ('train','validation','test'):
        labels={r['label'] for r in rows if r['split']==split}
        if labels!={0,1}:raise ValueError(f'{split} must contain both labels')
    group_splits={}
    for row in rows:
        group_splits.setdefault(str(row['group_id']),set()).add(row['split'])
    leaks=[group for group,splits in group_splits.items() if len(splits)>1]
    if leaks:raise ValueError(f'group leakage across splits: {len(leaks)} groups')
    extractor=EvidenceFeatureExtractor();dense=[];sparse_rows=[];labels=[];splits=[];content_splits={}
    for row in rows:
        eml=(base/row['eml']).resolve() if not Path(row['eml']).is_absolute() else Path(row['eml']).resolve()
        message=BytesParser(policy=policy.default).parsebytes(eml.read_bytes())
        if isinstance(row.get('analysis'),dict):
            result=row['analysis']
        else:
            result_path=(base/row['analysis_result']).resolve() if not Path(row['analysis_result']).is_absolute() else Path(row['analysis_result']).resolve()
            result=json.loads(result_path.read_text(encoding='utf-8'))
        text=message_text(message);digest=hashlib.sha256(text.encode()).hexdigest();content_splits.setdefault(digest,set()).add(row['split'])
        dense.append(extractor.vector(result));sparse_rows.append({} if args.objective_only else hashed_char_ngrams(text,args.text_bins));labels.append(row['label']);splits.append(row['split'])
    duplicates=sum(len(value)>1 for value in content_splits.values())
    if duplicates:raise ValueError(f'normalized message leakage across splits: {duplicates}')
    y=np.asarray(labels);dense=np.asarray(dense,float);indices={name:np.array([s==name for s in splits]) for name in ('train','validation','test')}
    scaler=StandardScaler().fit(dense[indices['train']]);scaled=(dense-scaler.mean_)/scaler.scale_
    row_idx=[];col_idx=[];values=[]
    for i,features in enumerate(sparse_rows):
        for col,value in features.items():row_idx.append(i);col_idx.append(col);values.append(value)
    text_bins=0 if args.objective_only else args.text_bins
    text_matrix=csr_matrix((values,(row_idx,col_idx)),shape=(len(rows),text_bins))
    matrix=hstack([csr_matrix(scaled),text_matrix],format='csr')
    model=LogisticRegression(max_iter=3000,class_weight='balanced',random_state=42,solver='liblinear',C=args.regularization_c)
    model.fit(matrix[indices['train']],y[indices['train']])
    probabilities={name:model.predict_proba(matrix[index])[:,1] for name,index in indices.items()}
    report={name:metrics(y[indices[name]],probabilities[name]) for name in ('validation','test')}
    gate={'passed':report['validation']['auc']>=args.min_validation_auc and report['validation']['fpr']<=args.max_validation_fpr and report['validation']['recall']>=args.min_validation_recall,
          'criteria':{'min_auc':args.min_validation_auc,'max_fpr':args.max_validation_fpr,'min_recall':args.min_validation_recall},'observed':report['validation']}
    report.update({'rows':len(rows),'split_counts':{name:int(indices[name].sum()) for name in indices},'validation_gate':gate,
                   'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
                   'training_parameters':{'regularization_c':args.regularization_c,'text_bins':text_bins,'objective_only':args.objective_only},
                   'limitations':'Generated or synthetic test data does not establish real-world performance. Keep test groups independent from prompt/template families.'})
    metrics_path=args.output.with_suffix('.metrics.json');metrics_path.parent.mkdir(parents=True,exist_ok=True)
    metrics_path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    if not gate['passed']:
        print(json.dumps(report,ensure_ascii=False,indent=2));raise SystemExit(2)
    coef=model.coef_[0];n=len(extractor.FEATURE_NAMES)
    artifact={'model_id':args.model_id,'schema_version':extractor.SCHEMA_VERSION,'feature_names':list(extractor.FEATURE_NAMES),
              'text_bins':text_bins,'positive_class':'label_1','decision_threshold':.5,
              'mean':scaler.mean_.tolist(),'scale':scaler.scale_.tolist(),'evidence_coef':coef[:n].tolist(),'text_coef':coef[n:].tolist(),
              'intercept':float(model.intercept_[0]),'validation_gate':gate,'manifest_sha256':report['manifest_sha256']}
    artifact['training_parameters']={'regularization_c':args.regularization_c,'text_bins':text_bins,'objective_only':args.objective_only}
    args.output.write_text(json.dumps(artifact,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
