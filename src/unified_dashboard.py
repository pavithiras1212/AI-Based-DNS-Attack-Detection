"""Unified Streamlit dashboard for the three DNS attack workstreams.

This is a research/demo interface. Tunneling metrics are loaded from saved
reports, amplification predictions use the saved flow classifier, and cache
poisoning checks are heuristic packet-triage alerts rather than proof of attack.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from src.cache_poisoning_checks import analyze_pcap
from src.detect_amplification import predict_flows

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "results" / "reports"
TUNNEL_REPORTS = REPORTS / "dns_tunneling"
AMPLIFICATION_REPORTS = REPORTS / "dns_amplification"
CACHE_REPORTS = REPORTS / "dns_cache_poisoning"
AMPLIFICATION_MODEL = (
    ROOT / "models" / "dns_amplification" / "dns_amplification_model.joblib"
)

st.set_page_config(
    page_title="DNS Attack Detection Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container {padding-top: 1.6rem; padding-bottom: 2.5rem; max-width: 1500px;}
      .hero {padding: 1.35rem 1.5rem; border-radius: 16px;
             border: 1px solid rgba(128,128,128,.25);
             background: linear-gradient(120deg, rgba(33,93,132,.16), rgba(38,145,125,.10));
             margin-bottom: 1.1rem;}
      .hero-kicker {text-transform: uppercase; letter-spacing: .14em; font-size: .75rem;
                    font-weight: 700; opacity: .72;}
      .hero-title {font-size: clamp(1.7rem, 3vw, 2.55rem); font-weight: 800;
                   letter-spacing: -.035em; line-height: 1.15; margin: .4rem 0 .55rem 0;}
      .hero-copy {max-width: 850px; opacity: .83; font-size: 1rem;}
      .small-note {font-size: .86rem; opacity: .82;}
      div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.24);
          border-radius: 12px; padding: .8rem 1rem; background: rgba(128,128,128,.035);}
    </style>
    <div class="hero">
      <div class="hero-kicker">Security analytics · Research prototype</div>
      <div class="hero-title">DNS Attack Detection Lab</div>
      <div class="hero-copy">One place to review DNS tunneling experiments, classify DNS amplification flow records,
      and inspect DNS cache-poisoning indicators from packet captures.</div>
    </div>
    """,
    unsafe_allow_html=True,
)


def read_json(path: Path, default=None):
    """Read a JSON report and return a fallback when it is missing or invalid."""
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return default


def read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError:
        return None


@st.cache_resource(show_spinner="Loading the amplification model…")
def load_amplification_bundle(model_path: str):
    return joblib.load(model_path)


tunnel_summary = read_json(TUNNEL_REPORTS / "tunneling_final_summary.json", [])
tunnel_row_split = read_json(TUNNEL_REPORTS / "tunneling_model_comparison.json", {})
amp_metrics = read_json(AMPLIFICATION_REPORTS / "metrics.json", {})

if not isinstance(tunnel_summary, list):
    tunnel_summary = []
if not isinstance(tunnel_row_split, dict):
    tunnel_row_split = {}
if not isinstance(amp_metrics, dict):
    amp_metrics = {}

with st.sidebar:
    st.markdown("## Navigation")
    st.caption("Choose a workstream from the tabs on the main page.")
    st.divider()
    st.markdown("### Workstreams")
    st.markdown("**01 · DNS tunneling**\n\nSaved stateful/stateless experiment reports")
    st.markdown("**02 · DNS amplification**\n\nRandom Forest flow classifier")
    st.markdown("**03 · Cache poisoning**\n\nRule-based PCAP triage")
    st.divider()
    st.caption("Use only traffic and datasets you are authorised to analyse. Uploaded captures are processed temporarily by this app; do not use a public deployment for sensitive traffic.")

overview_tab, tunneling_tab, amplification_tab, cache_tab = st.tabs(
    ["Overview", "DNS Tunneling", "DNS Amplification", "DNS Cache Poisoning"]
)

with overview_tab:
    st.subheader("Project overview")
    st.write("The project combines three distinct analysis approaches. Metrics are shown per workstream; they should not be compared as if they were one model or one shared test set.")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("#### DNS tunneling")
        st.metric("Saved model variants", "2" if tunnel_summary else "Reports unavailable")
        st.caption("Stateful and stateless feature families; experimental evaluation reports are available in the tunneling tab.")
    with c2:
        st.markdown("#### DNS amplification")
        if amp_metrics:
            st.metric("Random-holdout accuracy", f"{float(amp_metrics.get('accuracy', 0)):.2%}")
            st.caption(f"{amp_metrics.get('dataset_rows_used', '—'):,} CSV rows · {amp_metrics.get('feature_count', '—')} retained numeric features")
        else:
            st.metric("Saved metrics", "Not found")
    with c3:
        st.markdown("#### DNS cache poisoning")
        st.metric("Analysis type", "Heuristic triage")
        st.caption("Looks for unmatched responses and changing answer sets. Alerts are not proof of cache poisoning.")

    st.divider()
    st.markdown("#### Current evidence and limitations")
    st.info("**Amplification:** the displayed score comes from a random stratified holdout of the supplied flow CSV, not independent-capture or real-world validation.")
    st.warning("**Tunneling:** saved evaluations have class-imbalance limitations; the stateless random-row report shows zero attack precision/recall/F1. Review the per-model details before drawing conclusions.")
    st.warning("**Cache poisoning:** this is a rule-based review aid. Incomplete captures and legitimate DNS rotation can trigger alerts; suitable independent ground truth is not yet available.")

with tunneling_tab:
    st.subheader("DNS tunneling · Stateful vs stateless")
    st.write("This section displays committed experiment summaries and reports. It does not run a fresh prediction over uploaded traffic.")

    summary_by_family = {
        row.get("family", "unknown"): row for row in tunnel_summary if isinstance(row, dict)
    }
    family_cols = st.columns(2)
    for idx, family in enumerate(("stateful", "stateless")):
        row = summary_by_family.get(family)
        with family_cols[idx]:
            st.markdown(f"#### {family.title()} model")
            if not row:
                st.warning("Saved summary is missing for this model family.")
                continue
            m1, m2 = st.columns(2)
            m1.metric("Attack precision", f"{float(row.get('attack_precision', 0)):.1%}")
            m2.metric("Attack recall", f"{float(row.get('attack_recall', 0)):.1%}")
            m3, m4 = st.columns(2)
            m3.metric("Attack F1", f"{float(row.get('attack_f1', 0)):.1%}")
            m4.metric("Balanced accuracy", f"{float(row.get('balanced_accuracy', 0)):.1%}")
            st.caption(
                f"Features: {row.get('feature_count', '—')} · "
                f"Held-out attack files: {row.get('heldout_attack_file_count', '—')} · "
                f"Sample prediction check: {row.get('sample_prediction_check', 'not reported')}"
            )

    st.markdown("#### Random-row split comparison")
    if tunnel_row_split:
        chart_rows = []
        for family in ("stateful", "stateless"):
            row = tunnel_row_split.get(family, {})
            if row:
                chart_rows.append({
                    "Model": family.title(),
                    "Attack precision": float(row.get("attack_precision", 0)),
                    "Attack recall": float(row.get("attack_recall", 0)),
                    "Attack F1": float(row.get("attack_f1", 0)),
                    "Balanced accuracy": float(row.get("balanced_accuracy", 0)),
                })
        if chart_rows:
            chart_df = pd.DataFrame(chart_rows).set_index("Model")
            st.bar_chart(chart_df, y=["Attack precision", "Attack recall", "Attack F1", "Balanced accuracy"], y_label="Score", height=300)
        st.caption("These are the separate random-row split metrics in tunneling_model_comparison.json. They are not the held-out attack-file summary shown above.")
    else:
        st.info("Random-row comparison report not found in this checkout.")

    with st.expander("Read saved tunneling reports"):
        for report_name, title in (
            ("DNS_TUNNELING_FINAL_REPORT.md", "Tunneling final report"),
            ("stateful_final_report.txt", "Stateful final report"),
            ("stateless_final_report.txt", "Stateless final report"),
        ):
            report = read_text(TUNNEL_REPORTS / report_name)
            if report:
                st.markdown(f"**{title}**")
                st.code(report, language="text")
                st.download_button(
                    f"Download {report_name}",
                    data=report,
                    file_name=report_name,
                    mime="text/plain",
                    key=f"download_{report_name}",
                )

with amplification_tab:
    st.subheader("DNS amplification / DoS flow classifier")
    st.write("Upload a CSV of flow-feature records to classify them as `Benign` or `DrDoS_DNS`. A `Label` column, when present, is ignored during prediction.")

    if amp_metrics:
        metric_cols = st.columns(4)
        metric_cols[0].metric("Accuracy", f"{float(amp_metrics.get('accuracy', 0)):.2%}")
        metric_cols[1].metric("Attack precision", f"{float(amp_metrics.get('precision_attack', 0)):.2%}")
        metric_cols[2].metric("Attack recall", f"{float(amp_metrics.get('recall_attack', 0)):.2%}")
        metric_cols[3].metric("Attack F1", f"{float(amp_metrics.get('f1_attack', 0)):.2%}")
        st.caption(amp_metrics.get("validation_note", "Saved validation note not available."))

    if not AMPLIFICATION_MODEL.is_file():
        st.error("Saved amplification model is missing. Run `src/train_amplification.py` with the labelled dataset first.")
    else:
        uploaded_flows = st.file_uploader("Choose a flow-feature CSV", type=["csv"], key="amplification_csv")
        if uploaded_flows is not None:
            try:
                input_df = pd.read_csv(uploaded_flows, low_memory=False)
                bundle = load_amplification_bundle(str(AMPLIFICATION_MODEL))
                predictions = predict_flows(input_df, bundle)
                output_df = pd.concat(
                    [input_df.reset_index(drop=True), predictions.reset_index(drop=True)], axis=1
                )
                attack_count = int((predictions["predicted_label"] == "DrDoS_DNS").sum())
                total_count = len(predictions)
                p1, p2, p3 = st.columns(3)
                p1.metric("Rows analysed", f"{total_count:,}")
                p2.metric("Predicted DrDoS_DNS", f"{attack_count:,}")
                p3.metric("Predicted benign", f"{total_count - attack_count:,}")
                if total_count:
                    st.progress(attack_count / total_count, text=f"{attack_count / total_count:.1%} of rows predicted as DrDoS_DNS")
                st.dataframe(output_df.head(200), width="stretch", hide_index=True)
                if len(output_df) > 200:
                    st.caption("Preview limited to the first 200 rows. The download contains all predictions.")
                st.download_button(
                    "Download all predictions as CSV",
                    data=output_df.to_csv(index=False).encode("utf-8"),
                    file_name="dns_amplification_predictions.csv",
                    mime="text/csv",
                    width="stretch",
                )
            except Exception as exc:  # show actionable input errors in UI
                st.error(f"Could not analyse this CSV: {exc}")

    with st.expander("Show training evaluation details"):
        if amp_metrics:
            st.json({key: value for key, value in amp_metrics.items() if key not in {"feature_columns", "dropped_feature_columns"}})
            st.caption("A high random-holdout score does not demonstrate generalisation to independent captures or live networks.")
        else:
            st.info("Amplification metrics file not found.")

with cache_tab:
    st.subheader("DNS cache-poisoning · Packet capture triage")
    st.write("Upload a `.pcap` or `.pcapng` file to inspect DNS request/response patterns for heuristic alerts.")
    st.warning("An alert is a lead for analyst review, not proof of cache poisoning. Captures missing the original request and legitimate load balancing may produce alerts.")

    timeout_seconds = st.number_input(
        "Maximum request-to-response delay (seconds)", min_value=0.1, max_value=60.0, value=5.0, step=0.5
    )
    uploaded_capture = st.file_uploader("Choose a DNS packet capture", type=["pcap", "pcapng"], key="cache_capture")

    if uploaded_capture is not None:
        temp_path: str | None = None
        try:
            suffix = ".pcapng" if uploaded_capture.name.lower().endswith(".pcapng") else ".pcap"
            with tempfile.NamedTemporaryFile(prefix="dns_triage_", suffix=suffix, delete=False) as temporary:
                temporary.write(uploaded_capture.getvalue())
                temp_path = temporary.name
            with st.spinner("Reading packets and checking DNS responses…"):
                findings = analyze_pcap(temp_path, response_timeout_seconds=float(timeout_seconds))
            findings_df = pd.DataFrame(findings)
            if findings_df.empty:
                st.success("No heuristic findings were produced for this capture. This does not prove the traffic is benign.")
                st.metric("Findings", "0")
                # Keep the CSV schema useful even when there are no findings.
                st.download_button(
                    "Download empty findings CSV",
                    data=("timestamp,client_ip,server_ip,transaction_id,query_name,query_type,answer_records,rule,severity,message,packet_index\n").encode("utf-8"),
                    file_name="dns_cache_poisoning_findings.csv",
                    mime="text/csv",
                )
            else:
                rule_counts = findings_df["rule"].value_counts()
                k1, k2, k3 = st.columns(3)
                k1.metric("Findings", f"{len(findings_df):,}")
                k2.metric("Unmatched responses", f"{int((findings_df['rule'] == 'unmatched_response').sum()):,}")
                k3.metric("Conflicting answer sets", f"{int((findings_df['rule'] == 'conflicting_answers').sum()):,}")
                st.bar_chart(rule_counts.rename_axis("Rule").to_frame("Count"), height=240)
                st.dataframe(findings_df, width="stretch", hide_index=True)
                st.download_button(
                    "Download findings as CSV",
                    data=findings_df.to_csv(index=False).encode("utf-8"),
                    file_name="dns_cache_poisoning_findings.csv",
                    mime="text/csv",
                    width="stretch",
                )
        except Exception as exc:
            st.error(f"Could not analyse this capture: {exc}")
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except OSError:
                    pass

    st.caption("Capture uploads are written to a temporary file for parsing and deleted after analysis. This dashboard does not save uploaded captures as project data.")

st.divider()
st.caption("DNS Attack Detection Lab · Defensive research prototype · Review evidence and validation scope before operational decisions.")
