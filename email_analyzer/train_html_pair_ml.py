"""Train a destination-versus-official structural classifier with group CV."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler

from email_analyzer.html_pair_features import FEATURE_NAMES, SCHEMA_VERSION


def metrics(labels, scores, threshold=0.5):
    predictions = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {'n': len(labels), 'auc': float(roc_auc_score(labels, scores)),
            'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
            'fpr': float(fp / (fp + tn)) if fp + tn else 0.0,
            'recall': float(tp / (tp + fn)) if tp + fn else 0.0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--model-id', default='dise-html-pair-v1')
    parser.add_argument('--folds', type=int, default=5)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.manifest.read_text(encoding='utf-8').splitlines() if line.strip()]
    if len(rows) < 100:
        raise ValueError('At least 100 labeled page pairs are required')
    if any(row.get('schema_version') != SCHEMA_VERSION for row in rows):
        raise ValueError('Feature schema mismatch')
    x = np.asarray([[float(row['features'][name]) for name in FEATURE_NAMES] for row in rows])
    y = np.asarray([int(row['label']) for row in rows])
    groups = np.asarray([str(row['group_id']) for row in rows])
    unique_groups = np.unique(groups)
    if len(unique_groups) < args.folds or set(y) != {0, 1}:
        raise ValueError('Both labels and enough independent groups are required')
    scores = np.zeros(len(rows))
    for train, test in GroupKFold(args.folds).split(x, y, groups):
        if set(y[train]) != {0, 1} or set(y[test]) != {0, 1}:
            raise ValueError('Each group fold must contain both labels')
        scaler = StandardScaler().fit(x[train])
        classifier = LogisticRegression(C=0.1, max_iter=2000, class_weight='balanced').fit(scaler.transform(x[train]), y[train])
        scores[test] = classifier.predict_proba(scaler.transform(x[test]))[:, 1]
    observed = metrics(y, scores)
    gate = {'passed': observed['auc'] >= 0.75 and observed['fpr'] <= 0.15 and observed['recall'] >= 0.65,
            'criteria': {'min_auc': 0.75, 'max_fpr': 0.15, 'min_recall': 0.65}, 'observed': observed}
    scaler = StandardScaler().fit(x)
    classifier = LogisticRegression(C=0.1, max_iter=2000, class_weight='balanced').fit(scaler.transform(x), y)
    artifact = {'model_id': args.model_id, 'schema_version': SCHEMA_VERSION,
                'feature_names': list(FEATURE_NAMES), 'mean': scaler.mean_.tolist(),
                'scale': scaler.scale_.tolist(), 'coef': classifier.coef_[0].tolist(),
                'intercept': float(classifier.intercept_[0]), 'decision_threshold': 0.5,
                'training_rows': len(rows), 'training_groups': len(unique_groups), 'validation_gate': gate}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(gate, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
