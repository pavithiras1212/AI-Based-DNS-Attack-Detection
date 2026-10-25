"""Heuristic DNS response checks for possible cache-poisoning indicators.

Findings are traffic-analysis alerts, not proof that a DNS cache was poisoned.
"""

import argparse
import csv
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from scapy.all import DNS, IP, TCP, UDP, IPv6, rdpcap

DEFAULT_RESPONSE_TIMEOUT_SECONDS = 5.0
CSV_FIELDS = [
    "timestamp",
    "client_ip",
    "server_ip",
    "transaction_id",
    "query_name",
    "query_type",
    "answer_records",
    "rule",
    "severity",
    "message",
    "packet_index",
]


def _dns_name(value: Any) -> str:
    """Decode a DNS wire name and normalize it for comparisons."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).rstrip(".").lower()


def _endpoint(packet: Any) -> tuple[str, str, int, int] | None:
    """Return source IP, destination IP, source port, destination port."""
    if IP in packet:
        source_ip = str(packet[IP].src)
        destination_ip = str(packet[IP].dst)
    elif IPv6 in packet:
        source_ip = str(packet[IPv6].src)
        destination_ip = str(packet[IPv6].dst)
    else:
        return None

    if UDP in packet:
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
    elif TCP in packet:
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
    else:
        return None

    return source_ip, destination_ip, source_port, destination_port


def _first_record(section: Any) -> Any | None:
    """Handle scalar or list-valued DNS sections."""
    if section is None:
        return None
    if isinstance(section, (list, tuple)):
        return section[0] if section else None
    return section


def _question(dns: Any) -> tuple[str, int] | None:
    """Return the first DNS question name and type, if present."""
    question = _first_record(dns.qd)
    if question is None:
        return None

    try:
        name = _dns_name(question.qname)
        query_type = int(question.qtype)
    except (AttributeError, TypeError, ValueError):
        return None

    if not name:
        return None
    return name, query_type


def _answer_records(dns: Any) -> tuple[str, ...]:
    """Read answer records into a stable, comparable tuple."""
    section = dns.an
    if section is None:
        return ()

    if isinstance(section, (list, tuple)):
        answer_items = list(section)
    else:
        answer_items = []
        current = section
        seen = 0
        while (
            current is not None
            and hasattr(current, "type")
            and seen < 1000
        ):
            answer_items.append(current)
            current = getattr(current, "payload", None)
            seen += 1

    records: list[str] = []
    for answer in answer_items[:1000]:
        try:
            record_type = int(answer.type)
            record_name = _dns_name(answer.rrname)
            value = answer.rdata
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            records.append(f"{record_name}|{record_type}|{value}")
        except (AttributeError, TypeError, ValueError):
            continue

    return tuple(sorted(records))


def _make_finding(
    *,
    timestamp: float,
    client_ip: str,
    server_ip: str,
    transaction_id: int,
    query_name: str,
    query_type: int,
    answer_records: tuple[str, ...] = (),
    rule: str,
    message: str,
    packet_index: int,
) -> dict[str, Any]:
    """Build one standardized finding."""
    return {
        "timestamp": timestamp,
        "client_ip": client_ip,
        "server_ip": server_ip,
        "transaction_id": transaction_id,
        "query_name": query_name,
        "query_type": query_type,
        "answer_records": ";".join(answer_records),
        "rule": rule,
        "severity": "medium",
        "message": message,
        "packet_index": packet_index,
    }


def analyze_pcap(
    pcap_path: str | Path,
    response_timeout_seconds: float = DEFAULT_RESPONSE_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Analyze a PCAP for unmatched and conflicting DNS responses.

    A response is matched against an earlier request using its DNS transaction
    ID, question, reversed IP/port tuple, and response timing. Unmatched
    responses and differing answers are heuristic alerts, not proof of attack.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    if response_timeout_seconds <= 0:
        raise ValueError(
            "response_timeout_seconds must be greater than zero"
        )

    packets = rdpcap(str(path))
    pending: dict[tuple[Any, ...], deque[dict[str, Any]]] = defaultdict(deque)
    answers_seen: dict[
        tuple[str, str, int], set[tuple[str, ...]]
    ] = defaultdict(set)
    findings: list[dict[str, Any]] = []

    for packet_index, packet in enumerate(packets):
        if DNS not in packet:
            continue

        endpoint = _endpoint(packet)
        if endpoint is None:
            continue

        dns = packet[DNS]
        question = _question(dns)
        if question is None:
            continue

        query_name, query_type = question
        source_ip, destination_ip, source_port, destination_port = endpoint
        timestamp = float(packet.time)
        transaction_id = int(dns.id)

        if not bool(dns.qr):
            key = (
                transaction_id,
                query_name,
                query_type,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
            )
            pending[key].append(
                {
                    "timestamp": timestamp,
                    "client_ip": source_ip,
                    "server_ip": destination_ip,
                    "transaction_id": transaction_id,
                    "query_name": query_name,
                    "query_type": query_type,
                }
            )
            continue

        client_ip = destination_ip
        server_ip = source_ip
        reverse_key = (
            transaction_id,
            query_name,
            query_type,
            client_ip,
            server_ip,
            destination_port,
            source_port,
        )

        matching_query = None
        queue = pending.get(reverse_key)

        if queue:
            while queue:
                candidate = queue.popleft()
                elapsed = timestamp - candidate["timestamp"]
                if 0 <= elapsed <= response_timeout_seconds:
                    matching_query = candidate
                    break

            if not queue:
                pending.pop(reverse_key, None)

        answer_records = _answer_records(dns)

        if matching_query is None:
            findings.append(
                _make_finding(
                    timestamp=timestamp,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    transaction_id=transaction_id,
                    query_name=query_name,
                    query_type=query_type,
                    answer_records=answer_records,
                    rule="unmatched_response",
                    message=(
                        "DNS response has no matching request with the same "
                        "transaction ID, question, reversed endpoints, and timing."
                    ),
                    packet_index=packet_index,
                )
            )

        if answer_records:
            answer_key = (client_ip, query_name, query_type)
            previous_answers = answers_seen[answer_key]

            if previous_answers and answer_records not in previous_answers:
                findings.append(
                    _make_finding(
                        timestamp=timestamp,
                        client_ip=client_ip,
                        server_ip=server_ip,
                        transaction_id=transaction_id,
                        query_name=query_name,
                        query_type=query_type,
                        answer_records=answer_records,
                        rule="conflicting_answers",
                        message=(
                            "Different answer records were observed for the "
                            "same client, DNS name, and query type. Verify "
                            "whether this is legitimate DNS rotation or suspicious."
                        ),
                        packet_index=packet_index,
                    )
                )

            previous_answers.add(answer_records)

    return findings


def main() -> None:
    """Run the DNS heuristic and write the findings to a CSV report."""
    parser = argparse.ArgumentParser(
        description="Check a DNS PCAP for suspicious response patterns."
    )
    parser.add_argument(
        "pcap",
        help="Path to an input .pcap or .pcapng file",
    )
    parser.add_argument(
        "--output",
        default="results/reports/dns_cache_poisoning/findings.csv",
        help=(
            "Output CSV path "
            "(default: results/reports/dns_cache_poisoning/findings.csv)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_RESPONSE_TIMEOUT_SECONDS,
        help="Maximum response delay in seconds (default: 5)",
    )
    args = parser.parse_args()

    findings = analyze_pcap(
        args.pcap,
        response_timeout_seconds=args.timeout,
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=CSV_FIELDS,
        )
        writer.writeheader()
        writer.writerows(findings)

    print(f"Findings written: {len(findings)}")
    print(f"Output: {output_path.resolve()}")
    print("Heuristic findings do not prove cache poisoning.")


if __name__ == "__main__":
    main()


def analyze_packets(
    packets: Any,
    response_timeout_seconds: float = DEFAULT_RESPONSE_TIMEOUT_SECONDS,
):
    """Analyze packets and return findings in the DataFrame format expected by callers."""
    import os
    import tempfile

    import pandas as pd
    from scapy.utils import wrpcap

    if isinstance(packets, (str, Path)):
        findings = analyze_pcap(
            packets,
            response_timeout_seconds=response_timeout_seconds,
        )
    else:
        packet_list = list(packets)

        if not packet_list:
            return pd.DataFrame(columns=CSV_FIELDS + ["finding"])

        file_descriptor, temporary_path = tempfile.mkstemp(suffix=".pcap")
        os.close(file_descriptor)

        try:
            wrpcap(temporary_path, packet_list)
            findings = analyze_pcap(
                temporary_path,
                response_timeout_seconds=response_timeout_seconds,
            )
        finally:
            if os.path.exists(temporary_path):
                os.remove(temporary_path)

    result = pd.DataFrame(findings, columns=CSV_FIELDS)

    def legacy_finding(row):
        rule = str(row.get("rule", ""))
        message = str(row.get("message", ""))

        if rule == "unmatched_response":
            return (
                "Unmatched DNS response. No matching request was found. "
                "No timely matching request was found. " + message
            )

        if rule == "conflicting_answers":
            return (
                "Conflicting answers detected. "
                "Different answer set detected. Conflicting DNS answers observed. " + message
            )

        return message

    result["finding"] = result.apply(legacy_finding, axis=1)
    return result
