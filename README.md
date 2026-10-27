# AI-Based DNS Attack Detection System

A research prototype combining three DNS security workstreams in one Streamlit dashboard.

## Components

### DNS tunneling
Stateful and stateless model experiments with saved evaluation reports. Results have class-imbalance limitations and should not be treated as proof of performance on unseen network captures.

### DNS amplification / DoS
A Random Forest classifier predicts `Benign` or `DrDoS_DNS` from flow-feature CSV records. The supplied 6,703-row dataset produced 99.58% accuracy on a random stratified holdout. This is not independent-capture or live-network validation.

### DNS cache-poisoning triage
A rule-based PCAP/PCAPNG analyser checks request-response matching and differing DNS answer sets. Alerts are heuristic indicators, not proof that a cache was poisoned.

## Run locally (Windows PowerShell)

From the project root:

```powershell
py -m venv .venv
$python = ".\.venv\Scripts\python.exe"
& $python -m pip install -r .\requirements.txt
& $python -m pytest .\tests -v
& $python -m streamlit run .\src\unified_dashboard.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## Demo uploads

The `demo_files` directory contains:

- `dns_amplification_demo.csv` — 10 labelled flow-feature examples for the amplification upload.
- `dns_cache_poisoning_demo.pcap` — a synthetic capture designed to demonstrate a conflicting-answer alert.

These demonstrate the upload and analysis workflow; they are not real-world attack validation. The PCAP uses documentation-only IP addresses.

## Run cache-poisoning checks from the command line

```powershell
$python = ".\.venv\Scripts\python.exe"
& $python .\src\cache_poisoning_checks.py ".\demo_files\dns_cache_poisoning_demo.pcap" --output ".\results\reports\dns_cache_poisoning\findings.csv"
```

## Limitations

Random row splits can overstate generalisation to independent captures. The cache-poisoning component is heuristic rather than a trained ML detector. Incomplete captures, legitimate DNS rotation, and record changes can produce alerts. Independent validation against suitable labelled cache-poisoning captures remains incomplete.

Only analyse traffic you are authorised to inspect.
