"""Predict benign vs DrDoS_DNS labels for new flow records."""

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = (
    PROJECT_ROOT / "models" / "dns_amplification"
    / "dns_amplification_model.joblib"
)


def predict_flows(data: pd.DataFrame, bundle: dict) -> pd.DataFrame:
    """Return predictions and attack probabilities for flow-feature rows."""
    if not isinstance(data, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    data = data.copy()
    data.columns = data.columns.astype(str).str.strip()
    data = data.drop(columns=["Label"], errors="ignore")

    feature_columns = bundle["feature_columns"]
    data = data.loc[:, ~data.columns.duplicated()]

    for column in data.columns:
        data[column] = pd.to_numeric(data[column], errors="coerce")

    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.reindex(columns=feature_columns)

    if data.empty:
        raise ValueError("The input CSV contains no rows to predict.")

    model = bundle["model"]
    predictions = model.predict(data)
    probabilities = model.predict_proba(data)[:, 1]

    return pd.DataFrame(
        {
            "predicted_label": [
                "DrDoS_DNS" if value == 1 else "Benign"
                for value in predictions
            ],
            "attack_probability": probabilities,
        }
    )


def main():
    parser = argparse.ArgumentParser(
        description="Classify flows using the trained DNS DoS baseline."
    )
    parser.add_argument("input_csv", help="CSV containing flow features.")
    parser.add_argument(
        "--output",
        default="results/reports/dns_amplification/predictions.csv",
        help="Output CSV path (default: results/reports/dns_amplification/predictions.csv).",
    )
    parser.add_argument(
        "--model",
        default=str(DEFAULT_MODEL),
        help="Path to the saved model bundle.",
    )
    args = parser.parse_args()

    input_path = Path(args.input_csv).expanduser()
    model_path = Path(args.model).expanduser()
    output_path = Path(args.output).expanduser()

    if not input_path.is_file():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")
    if not model_path.is_file():
        raise FileNotFoundError(
            f"Trained model not found: {model_path}. Run train_amplification.py first."
        )

    bundle = joblib.load(model_path)
    data = pd.read_csv(input_path, low_memory=False)
    results = predict_flows(data, bundle)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_path, index=False)

    print(f"Rows predicted: {len(results)}")
    print("\nPrediction counts:")
    print(results["predicted_label"].value_counts().to_string())
    print(f"\nSaved predictions to: {output_path.resolve()}")
    print("Attack probability is a model score, not a guarantee of attack.")


if __name__ == "__main__":
    main()
