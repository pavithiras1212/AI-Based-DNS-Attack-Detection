
"""Held-out attack-file validation for DNS tunneling."""

from pathlib import Path
import json
import warnings

import joblib
import numpy as np
import pandas as pd

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
    confusion_matrix,
)

warnings.filterwarnings("ignore", category=FutureWarning)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/raw/dns_tunneling/Attacks_Light_Benign"
OUT = ROOT / "results/reports/dns_tunneling"
OUT.mkdir(parents=True, exist_ok=True)

SEED = 42


def load_family(family):
    frames = []

    for folder_name, label in [("Benign", 0), ("Attacks", 1)]:
        folder = DATA / folder_name
        files = sorted(folder.glob(f"{family}_features-*.csv"))

        if not files:
            raise FileNotFoundError(f"No matching CSVs in {folder}")

        for path in files:
            df = pd.read_csv(path, low_memory=False)
            df.columns = df.columns.astype(str).str.strip()

            X = df.drop(columns=["timestamp"], errors="ignore")
            X = X.select_dtypes(include="number")
            X = X.replace([np.inf, -np.inf], np.nan)
            X = X.dropna(axis=1, how="all")

            X["target"] = label
            X["source_file"] = path.name

            # Remove repeated rows only within the same source file.
            features = [c for c in X.columns
                        if c not in ("target", "source_file")]
            X = X.drop_duplicates(subset=features + ["target"])
            frames.append(X)

    data = pd.concat(frames, ignore_index=True, sort=False)

    feature_cols = [
        c for c in data.columns
        if c not in ("target", "source_file")
    ]

    data[feature_cols] = data[feature_cols].replace(
        [np.inf, -np.inf], np.nan
    )
    data = data.dropna(axis=1, how="all")

    feature_cols = [
        c for c in data.columns
        if c not in ("target", "source_file")
    ]

    return data, feature_cols


def evaluate_family(family):
    data, features = load_family(family)

    benign = data[data["target"] == 0].copy()
    attacks = data[data["target"] == 1].copy()
    attack_files = sorted(attacks["source_file"].unique())

    if len(attack_files) < 2:
        raise ValueError("Need at least two attack source files.")

    print(f"\n{'=' * 55}")
    print(f"{family.upper()} HELD-OUT ATTACK-FILE VALIDATION")
    print(f"{'=' * 55}")
    print(f"Numeric features: {len(features)}")
    print(f"Benign rows after within-file deduplication: {len(benign):,}")
    print(f"Attack rows after within-file deduplication: {len(attacks):,}")
    print(f"Attack files to hold out: {len(attack_files)}")

    fold_results = []

    for fold, held_out_file in enumerate(attack_files):
        # Keep the held-out attack file entirely out of training.
        test_attacks = attacks[
            attacks["source_file"] == held_out_file
        ].copy()

        train_attacks = attacks[
            attacks["source_file"] != held_out_file
        ].copy()

        # The dataset has one benign source file, so benign rows
        # must be split within that file. This is a limitation.
        train_benign, test_benign = train_test_split(
            benign,
            test_size=0.25,
            random_state=SEED + fold,
        )

        train_data = pd.concat(
            [train_benign, train_attacks],
            ignore_index=True,
        )
        test_data = pd.concat(
            [test_benign, test_attacks],
            ignore_index=True,
        )

        X_train = train_data[features]
        y_train = train_data["target"].astype(int)
        X_test = test_data[features]
        y_test = test_data["target"].astype(int)

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

        # The held-out file name is retained in each result.
        tn, fp, fn, tp = confusion_matrix(
            y_test, pred, labels=[0, 1]
        ).ravel()

        metrics = {
            "feature_family": family,
            "held_out_attack_file": held_out_file,
            "train_rows": int(len(train_data)),
            "test_benign_rows": int(len(test_benign)),
            "test_attack_rows": int(len(test_attacks)),
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
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        }

        fold_results.append(metrics)

        print(f"\nHeld-out file: {held_out_file}")
        print(f"Test attacks: {len(test_attacks):,}")
        print(f"Attack recall: {metrics['attack_recall']:.3f}")
        print(f"Attack precision: {metrics['attack_precision']:.3f}")
        print(f"Attack F1: {metrics['attack_f1']:.3f}")
        print(f"Balanced accuracy: {metrics['balanced_accuracy']:.3f}")
        print(
            f"Confusion matrix counts: TN={tn}, FP={fp}, "
            f"FN={fn}, TP={tp}"
        )

    results = pd.DataFrame(fold_results)
    csv_path = OUT / f"{family}_heldout_capture_results.csv"
    json_path = OUT / f"{family}_heldout_capture_results.json"

    results.to_csv(csv_path, index=False)
    json_path.write_text(
        json.dumps(fold_results, indent=2),
        encoding="utf-8",
    )

    print("\nMean across held-out attack files:")
    for metric in [
        "attack_precision",
        "attack_recall",
        "attack_f1",
        "balanced_accuracy",
    ]:
        print(f"{metric}: {results[metric].mean():.3f}")

    print(f"Saved fold results: {csv_path}")
    print(f"Saved detailed results: {json_path}")


def main():
    for family in ("stateful", "stateless"):
        evaluate_family(family)

    print("\nHeld-out attack-file validation completed.")
    print(
        "Limitation: benign test rows come from the same benign source "
        "file as training rows. Do not claim fully independent-capture "
        "validation for both classes."
    )


if __name__ == "__main__":
    main()

