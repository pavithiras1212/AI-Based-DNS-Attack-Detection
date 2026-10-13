
"""Summarize rows affected by conflicting numeric feature labels."""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw" / "dns_tunneling" / "Attacks_Light_Benign"
REPORTS = ROOT / "results" / "reports" / "dns_tunneling"
REPORTS.mkdir(parents=True, exist_ok=True)


def summarize(family):
    frames = []

    for folder_name, label in [("Benign", 0), ("Attacks", 1)]:
        folder = DATA / folder_name

        for path in sorted(folder.glob(f"{family}_features-*.csv")):
            df = pd.read_csv(path, low_memory=False)
            X = df.drop(columns=["timestamp"], errors="ignore")
            X = X.select_dtypes(include="number")
            X = X.replace([float("inf"), float("-inf")], float("nan"))
            X = X.dropna(axis=1, how="all")
            X["target"] = label
            X["source_file"] = path.name
            frames.append(X)

    if not frames:
        print(f"No data found for {family}.")
        return

    data = pd.concat(frames, ignore_index=True, sort=False)
    features = [
        c for c in data.columns
        if c not in ("target", "source_file")
    ]

    # Count labels per feature combination, ignoring source filename.
    unique_pairs = data.drop_duplicates(subset=features + ["target"])
    label_counts = unique_pairs.groupby(
        features, dropna=False
    )["target"].nunique()

    conflicting = label_counts[label_counts > 1]
    conflicting_rows = data.merge(
        conflicting.reset_index()[features],
        on=features,
        how="inner",
    )

    print(f"\n===== {family.upper()} =====")
    print(f"Total rows: {len(data):,}")
    print(f"Conflicting feature combinations: {len(conflicting):,}")
    print(f"Rows involved in conflicts: {len(conflicting_rows):,}")
    print("Conflicting rows by label:")
    print(conflicting_rows["target"].value_counts().sort_index())

    # Save only a summary, not the full dataset.
    report = (
        f"Feature family: {family}\n"
        f"Total rows: {len(data)}\n"
        f"Conflicting feature combinations: {len(conflicting)}\n"
        f"Rows involved in conflicts: {len(conflicting_rows)}\n"
        f"Conflicting rows by label:\n"
        f"{conflicting_rows['target'].value_counts().sort_index()}\n"
    )
    (REPORTS / f"{family}_conflict_summary.txt").write_text(
        report, encoding="utf-8"
    )


def main():
    summarize("stateful")
    summarize("stateless")
    print("\nSummary complete. Original CSV files were not modified.")


if __name__ == "__main__":
    main()
