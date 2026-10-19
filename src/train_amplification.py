"""Train and evaluate a separate DNS amplification/DoS flow classifier."""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = Path.home() / "OneDrive" / "Desktop" / "DNS" / "DNS-testing.csv"
MODEL_DIR = PROJECT_ROOT / "models" / "dns_amplification"
REPORT_DIR = PROJECT_ROOT / "results" / "reports" / "dns_amplification"
TARGET_COLUMN = "Label"
LABEL_MAP = {"Benign": 0, "DrDoS_DNS": 1}


def prepare_dataset(data: pd.DataFrame):
    """Clean labels and numeric flow features; return X, y, and dropped columns."""
    data = data.copy()
    data.columns = data.columns.astype(str).str.strip()

    if TARGET_COLUMN not in data.columns:
        raise ValueError(f"Dataset must contain a '{TARGET_COLUMN}' column.")

    labels = data[TARGET_COLUMN].astype("string").str.strip()
    valid = labels.isin(LABEL_MAP)
    data = data.loc[valid].copy()
    labels = labels.loc[valid]

    if data.empty or labels.nunique() != 2:
        raise ValueError(
            "Need both supported labels: Benign and DrDoS_DNS."
        )

    y = labels.map(LABEL_MAP).astype(int)
    features = data.drop(columns=[TARGET_COLUMN])

    # Convert feature columns to numbers; text-only columns are excluded.
    for column in features.columns:
        features[column] = pd.to_numeric(features[column], errors="coerce")

    features = features.replace([np.inf, -np.inf], np.nan)
    dropped = []

    unusable = [
        col for col in features.columns
        if features[col].isna().all()
    ]
    dropped.extend(unusable)
    features = features.drop(columns=unusable)

    constant = [
        col for col in features.columns
        if features[col].nunique(dropna=True) <= 1
    ]
    dropped.extend(constant)
    features = features.drop(columns=constant)

    if features.shape[1] == 0:
        raise ValueError("No usable numeric feature columns remain.")

    # Keep target and feature row indices aligned.
    features = features.reset_index(drop=True)
    y = y.reset_index(drop=True)

    return features, y, dropped


def train_and_evaluate(data: pd.DataFrame, output_root: Path = PROJECT_ROOT):
    """Train a reproducible baseline and write its model and evaluation reports."""
    X, y, dropped_columns = prepare_dataset(data)

    if y.value_counts().min() < 2:
        raise ValueError("Each label needs at least two rows for a stratified split.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    metrics = {
        "task": "Benign vs DrDoS_DNS flow classification",
        "positive_class": "DrDoS_DNS",
        "negative_class": "Benign",
        "dataset_rows_used": int(len(X)),
        "feature_count": int(X.shape[1]),
        "dropped_feature_columns": dropped_columns,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "random_state": 42,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
        "precision_attack": float(precision_score(y_test, predictions, zero_division=0)),
        "recall_attack": float(recall_score(y_test, predictions, zero_division=0)),
        "f1_attack": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix_labels": ["Benign", "DrDoS_DNS"],
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "validation_note": (
            "Random stratified holdout from the supplied CSV; not independent "
            "capture-level or real-world validation."
        ),
    }

    model_dir = output_root / "models" / "dns_amplification"
    report_dir = output_root / "results" / "reports" / "dns_amplification"
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "feature_columns": list(X.columns),
        "label_map": LABEL_MAP,
        "positive_class": "DrDoS_DNS",
        "task": metrics["task"],
    }
    joblib.dump(bundle, model_dir / "dns_amplification_model.joblib")

    (report_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    (report_dir / "classification_report.txt").write_text(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Benign", "DrDoS_DNS"],
            zero_division=0,
        ),
        encoding="utf-8",
    )

    importance = pd.DataFrame(
        {
            "feature": list(X.columns),
            "importance": model.named_steps["classifier"].feature_importances_,
        }
    ).sort_values("importance", ascending=False)
    importance.to_csv(report_dir / "feature_importance.csv", index=False)

    pd.DataFrame(
        {
            "actual_label": y_test.map({0: "Benign", 1: "DrDoS_DNS"}).to_numpy(),
            "predicted_label": pd.Series(predictions).map(
                {0: "Benign", 1: "DrDoS_DNS"}
            ).to_numpy(),
            "attack_probability": probabilities,
        }
    ).to_csv(report_dir / "test_predictions.csv", index=False)

    return metrics, model_dir, report_dir


def main():
    parser = argparse.ArgumentParser(
        description="Train a DNS DoS/amplification flow classifier."
    )
    parser.add_argument(
        "dataset",
        nargs="?",
        default=str(DEFAULT_DATASET),
        help="Path to the labelled CSV dataset.",
    )
    args = parser.parse_args()
    dataset_path = Path(args.dataset).expanduser()

    if not dataset_path.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}\n"
            "Pass the CSV path as the first command-line argument."
        )

    data = pd.read_csv(dataset_path, low_memory=False)
    metrics, model_dir, report_dir = train_and_evaluate(data)

    print("\n=== DNS AMPLIFICATION / DoS BASELINE ===")
    for key in (
        "dataset_rows_used",
        "feature_count",
        "train_rows",
        "test_rows",
        "accuracy",
        "balanced_accuracy",
        "precision_attack",
        "recall_attack",
        "f1_attack",
        "roc_auc",
    ):
        print(f"{key}: {metrics[key]}")

    print("\nConfusion matrix (rows=actual, columns=predicted; Benign, DrDoS_DNS):")
    print(np.array(metrics["confusion_matrix"]))
    print(f"\nModel saved to: {model_dir}")
    print(f"Reports saved to: {report_dir}")
    print("\nReminder: this random holdout is not independent-capture validation.")


if __name__ == "__main__":
    main()
