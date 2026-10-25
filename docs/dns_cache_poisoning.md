# DNS Cache-Poisoning Checks

## Status

This is an initial rule-based DNS response-integrity checker, not a trained AI classifier. Its findings do not prove that cache poisoning occurred.

## What it checks

The checker reads DNS packets from PCAP or PCAPNG captures and flags:

- Responses for which no matching request was observed in the capture.
- Different answer sets for the same queried name and query type from the same responding server.

These are review signals. Incomplete captures, DNS load balancing, CDNs, and legitimate DNS record changes can produce similar patterns.

## How to run the checker

From the project root, run the following command with the actual path to your capture file:

    .venv\Scripts\python.exe .\src\cache_poisoning_checks.py "C:\actual\path\capture.pcap" --output ".\results\reports\dns_cache_poisoning\findings.csv"

The example capture path is a placeholder. Do not run the command unchanged.

## Dataset limitations

The available flow dataset uses the labels Benign and DrDoS_DNS. These are not ground-truth labels for DNS cache poisoning and cannot establish cache-poisoning detection accuracy.

Synthetic packet tests validate basic software behavior only. They do not establish real-world detection accuracy.

## Tests

Run the cache-poisoning tests:

    .venv\Scripts\python.exe -m pytest .\tests\test_cache_poisoning.py -v

Run all project tests:

    .venv\Scripts\python.exe -m pytest .\tests -v

## Future work

- Validate against appropriately labelled real packet captures.
- Improve request-response correlation and duplicate-response analysis.
- Test malformed packets and capture-boundary cases.
- Measure false positives and false negatives against independent ground truth.
- Consider DNSSEC-aware validation.