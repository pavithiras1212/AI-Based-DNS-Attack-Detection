# AI-Based DNS Attack Detection System

A research prototype with two current components.

## DNS amplification

A Random Forest classifier predicts Benign versus DrDoS_DNS from labelled flow features.
The supplied 6,703-row CSV produced 99.58% accuracy on a random stratified holdout.
This is not independent-capture or real-world validation.

## DNS cache-poisoning triage

A rule-based analyser checks DNS request-response matching, response timing, and differing answer sets.
The five functional tests pass. These checks flag suspicious patterns; they do not prove cache poisoning.

## Run locally

Create and activate a virtual environment, then install dependencies:

```powershell
python -m pip install -r requirements.txt
python -m pytest .\tests -v
python -m streamlit run .\src\amplification_dashboard.py
```

## Run cache-poisoning checks on a capture

```powershell
python .\src\cache_poisoning_checks.py .\path\to\capture.pcap --output .\results\reports\dns_cache_poisoning\findings.csv
```

## Limitations

The cache-poisoning component is heuristic triage, not a trained ML model.
A partial capture can make benign responses appear unmatched, while legitimate DNS rotation can produce different answer sets.
Independent validation on labelled, suitable cache-poisoning data remains incomplete.
Only analyse traffic you are authorised to inspect.
