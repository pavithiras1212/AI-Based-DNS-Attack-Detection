import pandas as pd
import pytest

from src.train_amplification import prepare_dataset, train_and_evaluate


def test_prepare_dataset_drops_constant_and_non_numeric_columns():
    data = pd.DataFrame(
        {
            "Flow Duration": [10, 20, 30, 40],
            "Constant": [1, 1, 1, 1],
            "Text Only": ["x", "y", "z", "w"],
            "Label": ["Benign", "DrDoS_DNS", "Benign", "DrDoS_DNS"],
        }
    )

    X, y, dropped = prepare_dataset(data)

    assert list(X.columns) == ["Flow Duration"]
    assert y.tolist() == [0, 1, 0, 1]
    assert "Constant" in dropped
    assert "Text Only" in dropped


def test_prepare_dataset_rejects_missing_label_column():
    with pytest.raises(ValueError, match="Label"):
        prepare_dataset(pd.DataFrame({"feature": [1, 2, 3]}))


def test_training_writes_model_and_reports(tmp_path):
    # Synthetic data makes this test independent of the user's private CSV.
    count = 80
    data = pd.DataFrame(
        {
            "Flow Duration": list(range(count)),
            "Packet Count": [i * 2 + (i % 3) for i in range(count)],
            "Constant": [5] * count,
            "Label": ["Benign" if i % 2 == 0 else "DrDoS_DNS" for i in range(count)],
        }
    )

    metrics, model_dir, report_dir = train_and_evaluate(data, tmp_path)

    assert metrics["train_rows"] + metrics["test_rows"] == count
    assert metrics["feature_count"] == 2
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert (model_dir / "dns_amplification_model.joblib").is_file()
    assert (report_dir / "metrics.json").is_file()
    assert (report_dir / "classification_report.txt").is_file()
    assert (report_dir / "feature_importance.csv").is_file()
    assert (report_dir / "test_predictions.csv").is_file()
