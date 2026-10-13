
"""Find identical DNS feature rows carrying different labels."""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw" / "dns_tunneling" / "Attacks_Light_Benign"


def check_family(family):
    frames = []

    for folder_name, label in [("Benign", 0), ("Attacks", 1)]:
        folder = DATA / folder_name

        for path in sorted(folder.glob(f"{family}_features-*.csv")):
            df = pd.read_csv(path, low_memory=False)
            df["target"] = label
            df["source_file"] = path.name
            frames.append(df)

    if not frames:
        print(f"No files found for {family}.")
        return

    data = pd.concat(frames, ignore_index=True, sort=False)

    # Compare feature values only, excluding label and source filename.
    feature_cols = [
        c for c in data.columns
        if c not in ("target", "source_file")
    ]

    # Keep one row per feature combination and record its distinct labels.
    unique_rows = data[feature_cols + ["target"]].drop_duplicates()
    label_counts = unique_rows.groupby(feature_cols, dropna=False)[
        "target"
    ].nunique()

    conflict_keys = label_counts[label_counts > 1].reset_index()[
        feature_cols
    ]

    print(f"\n{'=' * 15} {family.upper()} {'=' * 15}")
    print(f"Total rows: {len(data):,}")
    print(f"Unique feature-label combinations: {len(unique_rows):,}")
    print(f"Feature combinations with conflicting labels: {len(conflict_keys):,}")

    print("\nConflicts by label:")
    print(data.groupby(feature_cols, dropna=False)["target"].nunique().value_counts())

    if not conflict_keys.empty:
        examples = data.merge(
            conflict_keys.head(10),
            on=feature_cols,
            how="inner",
        )
        print("\nExamples of conflicting rows:")
        


def main():
    check_family("stateful")
    check_family("stateless")
    print("\nCheck complete. No original files were modified.")


if __name__ == "__main__":
    main()
