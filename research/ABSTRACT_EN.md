# Uncertainty- and Availability-Aware Evidence Fusion for Multi-Engine Phishing Email Detection

## Abstract

Phishing email detection requires heterogeneous evidence from message semantics, sender authentication, URL and domain relationships, HTML structure, and attachment inspection. A single aggregate risk score may conflate missing engines, conflicting observations, and genuine absence of risk, thereby obscuring both decision rationale and failure causes. This study presents a multi-engine analysis framework that maps heterogeneous outputs into a shared evidence representation and compares uncertainty-preserving evidence fusion with learned meta-classifiers. We evaluated 10,000 synthetic emails organized into 15 independent scenario groups. To control scenario leakage and in-sample prediction leakage from the upstream semantic classifier, we used nested group cross-validation with 10 outer folds, up to five inner folds, and out-of-fold semantic probabilities for meta-classifier training. The semantic classifier alone achieved 98.85% accuracy, 97.88% recall, and a 0.18% false-positive rate. Logistic fusion achieved 99.03% accuracy, 98.26% recall, and a 0.20% false-positive rate, reducing false negatives from 106 to 87. The paired exact McNemar test yielded p=0.000912, while a scenario-group bootstrap estimated a 95% confidence interval of 0.011–0.427 percentage points for the accuracy improvement. However, the learned fusion model correctly classified only six of eight held-out real emails, providing no accuracy improvement over the conservative production policy. Ablation and engine-dropout experiments further showed that the current fusion model remained strongly dependent on semantic evidence. These findings indicate that learned fusion can produce a small but consistent improvement within synthetic scenario groups, while also demonstrating that synthetic performance is insufficient for operational promotion. The main contribution is therefore an auditable fusion and evaluation procedure that preserves uncertainty, records engine availability, prevents stacked-model leakage, and exposes failure modes rather than claiming established real-world superiority.

## Keywords

Phishing email detection; evidence fusion; uncertainty; nested group cross-validation; stacking; multi-engine security analysis

## Claimed contributions

1. A shared representation that joins semantic, authentication, URL/domain, HTML, attachment, and catalogue evidence while retaining engine availability.
2. An uncertainty-preserving evidence path that assigns unresolved conflict to ignorance instead of normalizing it into artificial confidence.
3. A leakage-controlled nested group evaluation protocol using out-of-fold upstream predictions for learned fusion.
4. Ablation, engine-dropout, natural-conflict, and held-out real-email analyses that identify where the fusion layer succeeds and fails.

## Claims to avoid

- The system has not established real-world phishing detection accuracy.
- The eight real emails are a case audit, not a statistically representative test set.
- Attachment-malware and live-HTML performance cannot be inferred from placeholder attachments and reserved synthetic domains.
- Multilingual generalization has not been established by language-specific independent test sets.
