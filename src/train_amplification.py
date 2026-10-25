"""Train and evaluate a DNS amplification/DoS flow classifier."""

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
DEFAULT_DATASET = (
    Path.home() / "OneDrive" / "Desktop" / "DNS" / "DNS-testing.csv"
)
TARGET_COLUMN = "Label"
LABEL_MAP = {"Benign": 0, "DrDoS_DNS": 1}

NON_PREDICTIVE_COLUMNS = {
    "Unnamed: 0",
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP",
}


def cleaned_columns(data: pd.DataFrame) -> set[str]:
    """Return normalized column names."""
    return set(data.columns.astype(str).str.strip())


def prepare_dataset(data: pd.DataFrame):
    """Clean labels and numeric features; return X, y, dropped columns."""
    cleaned = data.copy()
    cleaned.columns = cleaned.columns.astype(str).str.strip()

    if TARGET_COLUMN not in cleaned.columns:
        raise ValueError(
            f"Dataset must contain a '{TARGET_COLUMN}' column."
        )

    labels = cleaned[TARGET_COLUMN].astype("string").str.strip()
    canonical_labels = labels.str.casefold().map(
        {"benign": "Benign", "drdos_dns": "DrDoS_DNS"}
    )
    valid = canonical_labels.notna()

    cleaned = cleaned.loc[valid].reset_index(drop=True)
    canonical_labels = canonical_labels.loc[valid].reset_index(drop=True)

    if cleaned.empty or canonical_labels.nunique() != 2:
        raise ValueError(
            "Need both supported labels: Benign and DrDoS_DNS."
        )

    y = canonical_labels.map(LABEL_MAP).astype(int)

    columns_to_drop = [TARGET_COLUMN]
    columns_to_drop.extend(
        column
        for column in NON_PREDICTIVE_COLUMNS
        if column in cleaned.columns
    )
    features = cleaned.drop(columns=columns_to_drop)

    for column in features.columns:
        features[column] = pd.to_numeric(
            features[column], errors="coerce"
        )

    features = features.replace([np.inf, -np.inf], np.nan)

    dropped_columns = []
    all_missing = [
        column
        for column in features.columns
        if features[column].isna().all()
    ]
    dropped_columns.extend(all_missing)
    features = features.drop(columns=all_missing)

    constant_columns = [
        column
        for column in features.columns
        if features[column].nunique(dropna=True) <= 1
    ]
    dropped_columns.extend(constant_columns)
    features = features.drop(columns=constant_columns)

    if features.empty:
        raise ValueError("No usable numeric feature columns remain.")

    return (
        features.reset_index(drop=True),
        y.reset_index(drop=True),
        dropped_columns,
    )


def train_and_evaluate(
    data: pd.DataFrame,
    output_root: Path = PROJECT_ROOT,
):
    """Train a baseline model and write its model and reports."""
    X, y, dropped_columns = prepare_dataset(data)

    if y.value_counts().min() < 2:
        raise ValueError(
            "Each label needs at least two rows for a stratified split."
        )

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
        "dataset_rows_used": len(X),
        "feature_count": int(X.shape[1]),
        "feature_columns": list(X.columns),
        "dropped_feature_columns": dropped_columns,
        "excluded_identifier_columns": [
            column
            for column in NON_PREDICTIVE_COLUMNS
            if column in cleaned_columns(data)
        ],
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "random_state": 42,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_test, predictions)
        ),
        "precision_attack": float(
            precision_score(y_test, predictions, zero_division=0)
        ),
        "recall_attack": float(
            recall_score(y_test, predictions, zero_division=0)
        ),
        "f1_attack": float(
            f1_score(y_test, predictions, zero_division=0)
        ),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "confusion_matrix_labels": ["Benign", "DrDoS_DNS"],
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "validation_note": (
            "Random stratified holdout from the supplied CSV; this is not "
            "independent-capture or real-world validation."
        ),
    }

    model_dir = (
        Path(output_root) / "models" / "dns_amplification"
    )
    report_dir = (
        Path(output_root)
        / "results"
        / "reports"
        / "dns_amplification"
    )
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "feature_columns": list(X.columns),
            "label_map": LABEL_MAP,
            "positive_class": "DrDoS_DNS",
            "task": metrics["task"],
        },
        model_dir / "dns_amplification_model.joblib",
    )

    (report_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
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
            "importance": (
                model.named_steps["classifier"].feature_importances_
            ),
        }
    ).sort_values("importance", ascending=False)

    importance.to_csv(
        report_dir / "feature_importance.csv",
        index=False,
    )

    pd.DataFrame(
        {
            "actual_label": y_test.reset_index(drop=True).map(
                {0: "Benign", 1: "DrDoS_DNS"}
            ),
            "predicted_label": pd.Series(predictions).map(
                {0: "Benign", 1: "DrDoS_DNS"}
            ),
            "attack_probability": probabilities,
        }
    ).to_csv(
        report_dir / "test_predictions.csv",
        index=False,
    )

    return metrics, model_dir, report_dir


def main() -> None:
    """Load the dataset, train the model, and print key metrics."""
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

    print("\n=== DNS AMPLIFICATION / DoS MODEL ===")
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

    print(
        "\nConfusion matrix "
        "(rows=actual, columns=predicted; Benign, DrDoS_DNS):"
    )
    print(np.array(metrics["confusion_matrix"]))
    print(f"\nModel saved to: {model_dir}")
    print(f"Reports saved to: {report_dir}")
    print(
        "\nReminder: this random holdout is not independent-capture "
        "validation."
    )


if __name__ == "__main__":
    main()
