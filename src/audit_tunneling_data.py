
"""Audit DNS tunneling CSV files without modifying the originals."""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw" / "dns_tunneling" / "Attacks_Light_Benign"


def audit_family(family):
    print(f"\n{'=' * 20} {family.upper()} {'=' * 20}")

    files = []

    for folder_name, label in [("Benign", 0), ("Attacks", 1)]:
        folder = DATA / folder_name

        for path in sorted(folder.glob(f"{family}_features-*.csv")):
            df = pd.read_csv(path, low_memory=False)

            # Exclude metadata; compare the original feature values.
            features = df.copy()
            files.append((path.name, label, features))

            print(f"\nFile: {path.name}")
            print(f"Rows: {len(df):,}")
            print(f"Duplicate rows within file: {df.duplicated().sum():,}")
            print(f"Columns: {len(df.columns)}")

    print("\n--- Cross-file comparison ---")

    for i in range(len(files)):
        name_a, label_a, df_a = files[i]
        for j in range(i + 1, len(files)):
            name_b, label_b, df_b = files[j]

            common = [c for c in df_a.columns if c in df_b.columns]
            if not common:
                continue

            # Compare complete rows over shared columns.
            a = df_a[common].drop_duplicates()
            b = df_b[common].drop_duplicates()

            merged = a.merge(b, how="inner", on=common)
            if not merged.empty:
                label_note = (
                    "DIFFERENT LABEL FOLDERS"
                    if label_a != label_b else "same label folder"
                )
                print(
                    f"{name_a} <-> {name_b}: "
                    f"{len(merged):,} shared unique rows ({label_note})"
                )


def main():
    if not DATA.is_dir():
        print(f"Dataset folder not found: {DATA}")
        return

    audit_family("stateful")
    audit_family("stateless")
    print("\nAudit complete. No original files were modified.")


if __name__ == "__main__":
    main()


