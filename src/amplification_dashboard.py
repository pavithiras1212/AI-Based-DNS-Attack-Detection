"""Streamlit dashboard for the DNS amplification/DoS baseline."""

import json
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from src.detect_amplification import predict_flows


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = (
    ROOT / "models" / "dns_amplification"
    / "dns_amplification_model.joblib"
)
METRICS_PATH = (
    ROOT / "results" / "reports" / "dns_amplification"
    / "metrics.json"
)


st.set_page_config(
    page_title="DNS Attack Detection",
    page_icon="🛡️",
    layout="wide",
)

st.title("DNS Attack Detection")
st.subheader("DNS DoS / amplification flow classifier")
st.warning(
    "Research baseline: this model classifies flow records labelled "
    "Benign or DrDoS_DNS. It does not independently verify DNS tunneling, "
    "cache poisoning, or real-world attack conditions."
)

if not MODEL_PATH.is_file():
    st.error(
        "Trained model not found. Run src/train_amplification.py first."
    )
    st.stop()

bundle = joblib.load(MODEL_PATH)

if METRICS_PATH.is_file():
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    st.markdown("### Held-out evaluation")
    columns = st.columns(4)
    columns[0].metric("Accuracy", f"{metrics['accuracy']:.2%}")
    columns[1].metric("Attack precision", f"{metrics['precision_attack']:.2%}")
    columns[2].metric("Attack recall", f"{metrics['recall_attack']:.2%}")
    columns[3].metric("Attack F1", f"{metrics['f1_attack']:.2%}")
    st.caption(metrics["validation_note"])

st.markdown("### Analyse a CSV")
st.write(
    "Upload flow-feature records with columns matching the training dataset. "
    "The Label column is optional and is not used to make predictions."
)

uploaded = st.file_uploader("Choose a flow CSV file", type=["csv"])

if uploaded is not None:
    try:
        data = pd.read_csv(uploaded, low_memory=False)
        results = predict_flows(data, bundle)
        combined = pd.concat(
            [data.reset_index(drop=True), results.reset_index(drop=True)],
            axis=1,
        )

        total = len(results)
        attack_count = int((results["predicted_label"] == "DrDoS_DNS").sum())
        benign_count = total - attack_count

        st.markdown("### Prediction summary")
        c1, c2, c3 = st.columns(3)
        c1.metric("Rows analysed", total)
        c2.metric("Predicted DrDoS_DNS", attack_count)
        c3.metric("Predicted benign", benign_count)

        st.dataframe(combined.head(100), use_container_width=True)

        st.download_button(
            "Download all predictions as CSV",
            data=combined.to_csv(index=False).encode("utf-8"),
            file_name="dns_amplification_predictions.csv",
            mime="text/csv",
        )
    except Exception as exc:
        st.error(f"Could not analyse this file: {exc}")

st.caption(
    "Use only data you are authorised to analyse. Predictions are model "
    "outputs and should be reviewed before operational use."
)
