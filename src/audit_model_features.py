
"""Audit label conflicts in the numeric features used by the baseline."""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw" / "dns_tunneling" / "Attacks_Light_Benign"


def audit_family(family):
    frames = []

    for folder_name, label in [("Benign", 0), ("Attacks", 1)]:
        folder = DATA / folder_name

        for path in sorted(folder.glob(f"{family}_features-*.csv")):
            df = pd.read_csv(path, low_memory=False)

            # Match the baseline's numeric feature selection.
            X = df.drop(columns=["timestamp"], errors="ignore")
            X = X.select_dtypes(include="number")
            X = X.replace([float("inf"), float("-inf")], float("nan"))
            X = X.dropna(axis=1, how="all")

            X["target"] = label
            frames.append(X)

    print(f"\n{'=' * 12} {family.upper()} {'=' * 12}")

    if not frames:
        print("No matching CSV files found.")
        return

    data = pd.concat(frames, ignore_index=True, sort=False)

    feature_cols = [c for c in data.columns if c != "target"]

    # Count distinct labels for each numeric feature combination.
    unique_pairs = data.drop_duplicates(subset=feature_cols + ["target"])
    label_counts = unique_pairs.groupby(
        feature_cols, dropna=False
    )["target"].nunique()

    conflicts = label_counts[label_counts > 1]

    print(f"Rows examined: {len(data):,}")
    print(f"Numeric features: {len(feature_cols)}")
    print(f"Conflicting numeric feature combinations: {len(conflicts):,}")
    print("Original CSV files were not modified.")


def main():
    if not DATA.is_dir():
        print(f"Dataset directory not found: {DATA}")
        return

    audit_family("stateful")
    audit_family("stateless")


if __name__ == "__main__":
    main()
