
"""Utilities for loading and inspecting DNS datasets."""

from pathlib import Path

import pandas as pd


def load_csv(file_path: str | Path) -> pd.DataFrame:
    """Load a CSV file into a pandas DataFrame."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")

    return pd.read_csv(path)


def inspect_dataset(data: pd.DataFrame) -> None:
    """Print basic information about a dataset."""
    print("\n--- Dataset Inspection ---")
    print(f"Rows: {data.shape[0]}")
    print(f"Columns: {data.shape[1]}")

    print("\nColumn names:")
    print(data.columns.tolist())

    print("\nMissing values per column:")
    print(data.isnull().sum())

    print("\nFirst five records:")
    print(data.head())
