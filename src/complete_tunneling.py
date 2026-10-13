
"""Consolidate DNS tunneling results and check saved model artifacts."""

from pathlib import Path
import json
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "results" / "reports" / "dns_tunneling"
MODELS = ROOT / "models" / "dns_tunneling"
PROCESSED = ROOT / "data" / "processed" / "dns_tunneling"

REPORTS.mkdir(parents=True, exist_ok=True)

families = ["stateful", "stateless"]
summary = []
details = []

for family in families:
    model_path = MODELS / f"{family}_model.joblib"
    data_path = PROCESSED / f"{family}_corrected_numeric.csv"
    metrics_path = REPORTS / f"{family}_corrected_metrics.json"
    folds_path = REPORTS / f"{family}_heldout_capture_results.json"

    required = [model_path, data_path, metrics_path, folds_path]
    missing = [str(p) for p in required if not p.exists()]

    if missing:
        raise FileNotFoundError(
            f"Missing required files for {family}:\n" +
            "\n".join(missing)
        )

    model = joblib.load(model_path)
    data = pd.read_csv(data_path, low_memory=False)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    folds = json.loads(folds_path.read_text(encoding="utf-8"))

    features = [c for c in data.columns if c != "target"]
    if not features:
        raise ValueError(f"No model features found for {family}")

    # Verify that the saved model accepts the saved feature columns.
    sample = data[features].head(5)
    predictions = model.predict(sample)

    feature_path = REPORTS / f"{family}_feature_columns.json"
    feature_path.write_text(
        json.dumps(features, indent=2),
        encoding="utf-8",
    )

    mean_metrics = {
        metric: sum(row[metric] for row in folds) / len(folds)
        for metric in [
            "attack_precision",
            "attack_recall",
            "attack_f1",
            "balanced_accuracy",
        ]
    }

    summary.append({
        "family": family,
        "model_exists": True,
        "feature_count": len(features),
        "sample_prediction_check": "passed",
        "heldout_attack_file_count": len(folds),
        **mean_metrics,
    })

    details.append((family, metrics, mean_metrics, len(features)))

    print(f"\n{family.upper()}: model check passed")
    print(f"Features: {len(features)}")
    print(f"Sample predictions: {list(map(int, predictions))}")
    print(f"Mean held-out attack recall: {mean_metrics['attack_recall']:.3%}")
    print(f"Mean held-out attack F1: {mean_metrics['attack_f1']:.3%}")

# Save machine-readable comparison.
comparison_path = REPORTS / "tunneling_final_summary.json"
comparison_path.write_text(
    json.dumps(summary, indent=2),
    encoding="utf-8",
)

# Create the consolidated human-readable report.
lines = [
    "# DNS Tunneling Detection — Final Project Report",
    "",
    "## Objective",
    "Build machine-learning baselines to distinguish benign DNS traffic "
    "from light DNS tunneling attack traffic.",
    "",
    "## Dataset and features",
    "Dataset source: CIC-Bell-DNS-EXF-2021, using the local "
    "Attacks_Light_Benign dataset.",
    "",
    "Two numeric feature families were evaluated: stateful and stateless.",
    "",
    "## Random-split baseline results",
    "",
    "| Metric | Stateful | Stateless |",
    "|---|---:|---:|",
]

metric_names = [
    ("accuracy", "Accuracy"),
    ("balanced_accuracy", "Balanced accuracy"),
    ("attack_precision", "Attack precision"),
    ("attack_recall", "Attack recall"),
    ("attack_f1", "Attack F1"),
    ("roc_auc", "ROC-AUC"),
]

metrics_by_family = {
    family: metrics for family, metrics, _, _ in details
}

for key, label in metric_names:
    a = metrics_by_family["stateful"].get(key)
    b = metrics_by_family["stateless"].get(key)
    if a is not None and b is not None:
        lines.append(f"| {label} | {a:.4f} | {b:.4f} |")

lines += [
    "",
    "## Held-out attack-file evaluation",
    "",
    "| Model | Attack files | Mean precision | Mean recall | Mean F1 | "
    "Mean balanced accuracy |",
    "|---|---:|---:|---:|---:|---:|",
]

for item in summary:
    lines.append(
        f"| {item['family']} | {item['heldout_attack_file_count']} | "
        f"{item['attack_precision']:.3f} | "
        f"{item['attack_recall']:.3f} | "
        f"{item['attack_f1']:.3f} | "
        f"{item['balanced_accuracy']:.3f} |"
    )

lines += [
    "",
    "## Findings",
    "",
    "- Both feature families produced working Random Forest baselines.",
    "- The stateful model had higher mean attack recall in the held-out "
    "attack-file experiment.",
    "- The stateless model had a slightly higher mean attack F1-score.",
    "- Precision below 1.0 indicates false-positive predictions.",
    "- Numeric feature combinations with conflicting labels were found. "
    "The corrected baseline retained both labels and removed only exact "
    "feature-plus-label duplicates.",
    "",
    "## Limitations",
    "",
    "- The benign test observations came from the same benign source file "
    "used for training; fully independent-capture validation is not complete.",
    "- Held-out attack-file results do not establish generalization to all "
    "DNS tunneling tools, networks, or attack strengths.",
    "- The saved models are baseline candidates, not production-validated "
    "detectors.",
    "- Further testing is needed before operational deployment.",
    "",
    "## Saved artifacts",
    "",
    "- Stateful and stateless model files: `models/dns_tunneling/`",
    "- Corrected baseline metrics and reports: `results/reports/dns_tunneling/`",
    "- Held-out attack-file metrics: `*_heldout_capture_results.csv`",
    "- Confusion matrices and feature importance: `results/figures/dns_tunneling/`",
    "- Model input feature lists: `*_feature_columns.json`",
    "",
    "## Status",
    "",
    "The dataset analysis, baseline training, and held-out attack-file "
    "experiments are documented. Independent benign-capture validation "
    "remains an explicit limitation.",
    "",
]

report_path = REPORTS / "DNS_TUNNELING_FINAL_REPORT.md"
report_path.write_text("\n".join(lines), encoding="utf-8")

print("\n" + "=" * 55)
print("DNS TUNNELING FINALIZATION CHECK COMPLETE")
print("=" * 55)
print(f"Consolidated report: {report_path}")
print(f"Model comparison: {comparison_path}")
print("Both saved models loaded and accepted sample predictions.")
print("No retraining was performed.")
print("Original raw CSV files were not modified.")
