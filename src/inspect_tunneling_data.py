
"""Inspect the DNS tunneling dataset without modifying original files."""

from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "dns_tunneling"
    / "Attacks_Light_Benign"
)

FOLDERS = ["Attacks", "Benign"]


def main():
    print("=" * 60)
    print("DNS TUNNELING DATASET INSPECTION")
    print("=" * 60)

    for folder_name in FOLDERS:
        folder = DATA_DIR / folder_name

        print(f"\n{'=' * 20} {folder_name} {'=' * 20}")

        if not folder.is_dir():
            print(f"Folder not found: {folder}")
            continue

        csv_files = sorted(folder.glob("*.csv"))

        if not csv_files:
            print("No CSV files found.")
            continue

        for file_path in csv_files:
            print(f"\nFile: {file_path.name}")
            print(f"Size: {file_path.stat().st_size / 1024:.1f} KB")

            try:
                data = pd.read_csv(file_path, nrows=5)

                print(f"Columns ({len(data.columns)}):")
                print(data.columns.tolist())
                print("\nFirst 5 rows:")
                print(data.head().to_string(index=False))

            except Exception as error:
                print(f"Could not inspect file: {error}")

    print("\nInspection complete. Original files were not modified.")


if __name__ == "__main__":
    main()
