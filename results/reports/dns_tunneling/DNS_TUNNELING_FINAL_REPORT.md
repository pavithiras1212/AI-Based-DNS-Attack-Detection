# DNS Tunneling Detection — Final Project Report

## Objective
Build machine-learning baselines to distinguish benign DNS traffic from light DNS tunneling attack traffic.

## Dataset and features
Dataset source: CIC-Bell-DNS-EXF-2021, using the local Attacks_Light_Benign dataset.

Two numeric feature families were evaluated: stateful and stateless.

## Random-split baseline results

| Metric | Stateful | Stateless |
|---|---:|---:|
| Accuracy | 0.9895 | 0.9827 |
| Balanced accuracy | 0.8506 | 0.7858 |
| Attack precision | 0.3929 | 0.4118 |
| Attack recall | 0.7097 | 0.5833 |
| Attack F1 | 0.5057 | 0.4828 |
| ROC-AUC | 0.9606 | 0.8910 |

## Held-out attack-file evaluation

| Model | Attack files | Mean precision | Mean recall | Mean F1 | Mean balanced accuracy |
|---|---:|---:|---:|---:|---:|
| stateful | 6 | 0.647 | 0.981 | 0.776 | 0.985 |
| stateless | 6 | 0.677 | 0.955 | 0.790 | 0.969 |

## Findings

- Both feature families produced working Random Forest baselines.
- The stateful model had higher mean attack recall in the held-out attack-file experiment.
- The stateless model had a slightly higher mean attack F1-score.
- Precision below 1.0 indicates false-positive predictions.
- Numeric feature combinations with conflicting labels were found. The corrected baseline retained both labels and removed only exact feature-plus-label duplicates.

## Limitations

- The benign test observations came from the same benign source file used for training; fully independent-capture validation is not complete.
- Held-out attack-file results do not establish generalization to all DNS tunneling tools, networks, or attack strengths.
- The saved models are baseline candidates, not production-validated detectors.
- Further testing is needed before operational deployment.

## Saved artifacts

- Stateful and stateless model files: `models/dns_tunneling/`
- Corrected baseline metrics and reports: `results/reports/dns_tunneling/`
- Held-out attack-file metrics: `*_heldout_capture_results.csv`
- Confusion matrices and feature importance: `results/figures/dns_tunneling/`
- Model input feature lists: `*_feature_columns.json`

## Status

The dataset analysis, baseline training, and held-out attack-file experiments are documented. Independent benign-capture validation remains an explicit limitation.
