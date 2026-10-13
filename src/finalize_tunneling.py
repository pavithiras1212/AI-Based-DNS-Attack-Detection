
"""Corrected baseline evaluation for DNS tunneling."""

from pathlib import Path
import json
import warnings

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

warnings.filterwarnings("ignore", category=FutureWarning)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/raw/dns_tunneling/Attacks_Light_Benign"
OUT = ROOT / "results/reports/dns_tunneling"
FIG = ROOT / "results/figures/dns_tunneling"
MODEL_DIR = ROOT / "models/dns_tunneling"
PROCESSED = ROOT / "data/processed/dns_tunneling"

for folder in (OUT, FIG, MODEL_DIR, PROCESSED):
    folder.mkdir(parents=True, exist_ok=True)

SEED = 42


def run_model(family):
    frames = []

    for folder_name, label in [("Benign", 0), ("Attacks", 1)]:
        folder = DATA / folder_name
        files = sorted(folder.glob(f"{family}_features-*.csv"))

        if not files:
            raise FileNotFoundError(f"No CSV files found in {folder}")

        for path in files:
            df = pd.read_csv(path, low_memory=False)
            df.columns = df.columns.astype(str).str.strip()

            X = df.drop(columns=["timestamp"], errors="ignore")
            X = X.select_dtypes(include="number")
            X = X.replace([np.inf, -np.inf], np.nan)
            X = X.dropna(axis=1, how="all")

            X["target"] = label
            frames.append(X)

    # Align features across all files.
    data = pd.concat(frames, ignore_index=True, sort=False)

    feature_cols = [
        c for c in data.columns if c != "target"
    ]
    data[feature_cols] = data[feature_cols].replace(
        [np.inf, -np.inf], np.nan
    )
    data = data.dropna(axis=1, how="all")

    feature_cols = [
        c for c in data.columns if c != "target"
    ]

    # Keep BOTH labels when the same feature vector has conflicting labels.
    # Remove only identical feature + label combinations.
    original_rows = len(data)
    conflicting_labels = data.groupby(
        feature_cols, dropna=False
    )["target"].nunique()

    conflict_count = int((conflicting_labels > 1).sum())

    data = data.drop_duplicates(
        subset=feature_cols + ["target"]
    ).reset_index(drop=True)

    X = data[feature_cols]
    y = data["target"].astype(int)

    print(f"\n===== {family.upper()} =====")
    print(f"Original rows: {original_rows:,}")
    print(f"Conflicting numeric combinations: {conflict_count:,}")
    print(f"Rows after exact feature+label deduplication: {len(data):,}")
    print("Class counts (0=benign, 1=attack):")
    print(y.value_counts().sort_index().to_string())

    if y.nunique() != 2 or y.value_counts().min() < 5:
        raise ValueError(
            f"{family}: too few examples in a class for evaluation."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=SEED,
        stratify=y,
    )

    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=SEED,
            n_jobs=-1,
        )),
    ])

    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "feature_family": family,
        "original_rows": int(original_rows),
        "conflicting_numeric_combinations": conflict_count,
        "rows_after_deduplication": int(len(data)),
        "numeric_feature_count": len(feature_cols),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "test_benign_rows": int((y_test == 0).sum()),
        "test_attack_rows": int((y_test == 1).sum()),
        "accuracy": float(accuracy_score(y_test, pred)),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_test, pred)
        ),
        "attack_precision": float(
            precision_score(y_test, pred, zero_division=0)
        ),
        "attack_recall": float(
            recall_score(y_test, pred, zero_division=0)
        ),
        "attack_f1": float(
            f1_score(y_test, pred, zero_division=0)
        ),
        "roc_auc": float(roc_auc_score(y_test, prob)),
        "evaluation_method": "Stratified random row split; preliminary only",
    }

    joblib.dump(model, MODEL_DIR / f"{family}_model.joblib")
    data.to_csv(
        PROCESSED / f"{family}_corrected_numeric.csv",
        index=False,
    )

    with (OUT / f"{family}_corrected_metrics.json").open(
        "w", encoding="utf-8"
    ) as f:
        json.dump(metrics, f, indent=2)

    with (OUT / f"{family}_corrected_report.txt").open(
        "w", encoding="utf-8"
    ) as f:
        f.write(json.dumps(metrics, indent=2))
        f.write("\n\n")
        f.write(classification_report(
            y_test,
            pred,
            labels=[0, 1],
            target_names=["Benign", "Attack"],
            zero_division=0,
        ))
        f.write("\nConfusion matrix:\n")
        f.write(str(confusion_matrix(y_test, pred, labels=[0, 1])))
        f.write(
            "\n\nLimitations: random row split; repeated feature vectors "
            "may occur in both sets. Conflicting labels remain in the data. "
            "Independent-capture validation is still required.\n"
        )

    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay.from_predictions(
        y_test, pred,
        labels=[0, 1],
        display_labels=["Benign", "Attack"],
        cmap="Blues",
        ax=ax,
        colorbar=False,
    )
    ax.set_title(f"{family.title()} DNS Tunneling")
    fig.tight_layout()
    fig.savefig(FIG / f"{family}_corrected_confusion_matrix.png", dpi=160)
    plt.close(fig)

    importance = pd.DataFrame({
        "feature": feature_cols,
        "importance": model.named_steps[
            "classifier"
        ].feature_importances_,
    }).sort_values("importance", ascending=False)

    importance.to_csv(
        OUT / f"{family}_corrected_feature_importance.csv",
        index=False,
    )

    print("\nMETRICS")
    print(json.dumps(metrics, indent=2))
    print("\nClassification report:")
    print(classification_report(
        y_test, pred,
        labels=[0, 1],
        target_names=["Benign", "Attack"],
        zero_division=0,
    ))
    print(f"Saved report: {OUT / f'{family}_corrected_report.txt'}")


def main():
    for family in ("stateful", "stateless"):
        run_model(family)

    print("\nBoth corrected baseline evaluations completed.")
    print("Original raw CSV files were not modified.")
    print("Independent-capture validation remains to be done.")


if __name__ == "__main__":
    main()

