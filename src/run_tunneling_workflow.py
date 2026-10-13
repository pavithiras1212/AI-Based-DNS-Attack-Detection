
"""Quick validation, EDA and baseline for DNS tunneling."""

from pathlib import Path
import warnings

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)

warnings.filterwarnings("ignore", category=FutureWarning)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw" / "dns_tunneling" / "Attacks_Light_Benign"
FIGURES = ROOT / "results" / "figures" / "dns_tunneling"
REPORTS = ROOT / "results" / "reports" / "dns_tunneling"
PROCESSED = ROOT / "data" / "processed" / "dns_tunneling"

for folder in (FIGURES, REPORTS, PROCESSED):
    folder.mkdir(parents=True, exist_ok=True)


def load_family(family):
    """Load matching attack and benign CSVs; label by source folder."""
    frames = []

    for folder_name, label in (("Attacks", 1), ("Benign", 0)):
        folder = DATA / folder_name
        files = sorted(folder.glob(f"{family}_features-*.csv"))

        if not files:
            print(f"WARNING: No {family} CSVs in {folder}")
            continue

        for path in files:
            try:
                df = pd.read_csv(path, low_memory=False)
                if df.empty:
                    print(f"Skipping empty file: {path.name}")
                    continue

                # Label comes from the documented source folder.
                df["target"] = label
                df["source_file"] = path.name
                frames.append(df)
                print(f"Loaded {path.name}: {len(df):,} rows")
            except Exception as exc:
                print(f"Could not read {path.name}: {exc}")

    if not frames:
        return pd.DataFrame()

    return pd.concat(frames, ignore_index=True, sort=False)


def analyse_and_train(family):
    print(f"\n{'=' * 18} {family.upper()} FEATURES {'=' * 18}")
    df = load_family(family)

    if df.empty:
        print("No data loaded. Check DATA path and filenames.")
        return

    # Validation summary
    print(f"\nCombined shape: {df.shape}")
    print("\nClass counts (0=benign, 1=attack):")
    print(df["target"].value_counts().sort_index())
    print("\nMissing values, top 15 columns:")
    print(df.isna().sum().sort_values(ascending=False).head(15))
    print(f"\nExact duplicate rows: {df.drop(columns=['source_file']).duplicated().sum()}")

    df.drop_duplicates(inplace=True)
    df.to_csv(PROCESSED / f"{family}_combined_labelled.csv", index=False)

    # Use numeric predictors only. Exclude target and timestamp.
    X = df.drop(columns=["target", "source_file"], errors="ignore")
    X = X.drop(columns=["timestamp"], errors="ignore")
    X = X.select_dtypes(include="number")
    X = X.replace([float("inf"), float("-inf")], float("nan"))

    y = df["target"].astype(int)

    if X.shape[1] == 0:
        print("No numeric features available; cannot train.")
        return

    # Drop columns that have no usable values.
    X = X.dropna(axis=1, how="all")
    if X.shape[1] == 0:
        print("All numeric features are empty; cannot train.")
        return

    print(f"\nNumeric feature count: {X.shape[1]}")
    print("Features:", X.columns.tolist())

    # EDA: descriptive statistics
    stats = X.describe().T
    stats.to_csv(REPORTS / f"{family}_descriptive_statistics.csv")

    # EDA: missingness and feature distributions
    missing = X.isna().mean().sort_values(ascending=False)
    missing.head(20).to_csv(REPORTS / f"{family}_missingness.csv")

    sample = df.sample(min(5000, len(df)), random_state=42)
    plot_cols = [
        c for c in ["entropy", "len", "subdomain_length",
                    "rr_name_entropy", "rr_name_length", "ttl_mean"]
        if c in sample.columns
    ]

    if plot_cols:
        for col in plot_cols:
            plt.figure(figsize=(7, 4))
            sns.histplot(
                data=sample, x=col, hue="target",
                bins=30, element="step", stat="density",
                common_norm=False,
            )
            plt.title(f"{family}: {col} by class")
            plt.tight_layout()
            plt.savefig(FIGURES / f"{family}_{col}_distribution.png", dpi=120)
            plt.close()

    # Correlation heatmap on a manageable numeric sample.
    corr_cols = X.columns[:20]
    if len(corr_cols) >= 2:
        plt.figure(figsize=(11, 8))
        sns.heatmap(
            X[corr_cols].sample(min(5000, len(X)), random_state=42).corr(),
            cmap="coolwarm", center=0,
        )
        plt.title(f"{family}: numeric feature correlations")
        plt.tight_layout()
        plt.savefig(FIGURES / f"{family}_correlation.png", dpi=120)
        plt.close()

    # Baseline model. This random row split is preliminary, not final
    # evidence of generalisation across separate captures/sessions.
    if y.nunique() != 2 or y.value_counts().min() < 2:
        print("Need at least two examples per class to train/test.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=100, random_state=42,
            class_weight="balanced", n_jobs=-1,
        ),
    )

    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    report = classification_report(
        y_test, pred, labels=[0, 1],
        target_names=["Benign", "Attack"],
        zero_division=0,
    )

    results = (
        f"Feature family: {family}\n"
        f"Rows after deduplication: {len(df)}\n"
        f"Numeric features: {X.shape[1]}\n"
        f"Accuracy: {accuracy_score(y_test, pred):.4f}\n"
        f"Attack F1: {f1_score(y_test, pred, pos_label=1, zero_division=0):.4f}\n\n"
        f"Classification report:\n{report}\n"
        f"Confusion matrix (rows=actual, columns=predicted; "
        f"Benign then Attack):\n{confusion_matrix(y_test, pred, labels=[0, 1])}\n"
        "\nCAUTION: Preliminary random-row split. Related rows from the same "
        "capture may occur in both sets; do not treat these metrics as final.\n"
    )

    (REPORTS / f"{family}_baseline_results.txt").write_text(
        results, encoding="utf-8"
    )
    print("\n" + results)
    print(f"Reports saved in: {REPORTS}")
    print(f"Plots saved in: {FIGURES}")


def main():
    print("DNS TUNNELING: VALIDATION, EDA AND BASELINE")
    print(f"Dataset folder: {DATA}")

    if not DATA.is_dir():
        print("ERROR: Dataset folder not found. Check the folder path.")
        return

    # Analyse stateful and stateless features separately.
    analyse_and_train("stateful")
    analyse_and_train("stateless")

    print("\nWorkflow finished. Review the reports before trusting metrics.")


if __name__ == "__main__":
    main()
