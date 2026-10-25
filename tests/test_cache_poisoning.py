
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether

from src.cache_poisoning_checks import analyze_packets


def make_packet(
    src,
    dst,
    is_response,
    answer_ip=None,
    timestamp=1,
    source_port=None,
    destination_port=None,
    txid=10,
):
    source_port = source_port or (53 if is_response else 53000)
    destination_port = destination_port or (53000 if is_response else 53)

    dns = DNS(
        id=txid,
        qr=int(is_response),
        qd=DNSQR(qname="example.test", qtype="A"),
        an=(
            DNSRR(rrname="example.test", type="A", rdata=answer_ip)
            if is_response and answer_ip
            else None
        ),
        ancount=int(bool(is_response and answer_ip)),
    )

    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=source_port, dport=destination_port)
        / dns
    )
    packet.time = timestamp
    return packet


def test_matching_request_and_response():
    packets = [
        make_packet("192.0.2.10", "192.0.2.53", False, timestamp=1),
        make_packet(
            "192.0.2.53",
            "192.0.2.10",
            True,
            answer_ip="192.0.2.1",
            timestamp=2,
        ),
    ]
    assert analyze_packets(packets).empty


def test_unmatched_response_is_flagged():
    packet = make_packet(
        "192.0.2.53",
        "192.0.2.10",
        True,
        answer_ip="192.0.2.1",
    )
    result = analyze_packets([packet])
    assert len(result) == 1
    assert "No timely matching request" in result.iloc[0]["finding"]


def test_conflicting_answers_are_flagged():
    packets = [
        make_packet("192.0.2.10", "192.0.2.53", False, timestamp=1),
        make_packet(
            "192.0.2.53", "192.0.2.10", True,
            answer_ip="192.0.2.1", timestamp=2,
        ),
        make_packet("192.0.2.10", "192.0.2.53", False, timestamp=3),
        make_packet(
            "192.0.2.53", "192.0.2.10", True,
            answer_ip="203.0.113.9", timestamp=4,
        ),
    ]
    result = analyze_packets(packets)
    assert len(result) == 1
    assert "Different answer set" in result.iloc[0]["finding"]


def test_response_with_wrong_source_port_is_unmatched():
    packets = [
        make_packet("192.0.2.10", "192.0.2.53", False, timestamp=1),
        make_packet(
            "192.0.2.53",
            "192.0.2.10",
            True,
            answer_ip="192.0.2.1",
            timestamp=2,
            source_port=5353,
        ),
    ]
    result = analyze_packets(packets)
    assert len(result) == 1
    assert "No timely matching request" in result.iloc[0]["finding"]


def test_late_response_is_unmatched():
    packets = [
        make_packet("192.0.2.10", "192.0.2.53", False, timestamp=1),
        make_packet(
            "192.0.2.53",
            "192.0.2.10",
            True,
            answer_ip="192.0.2.1",
            timestamp=20,
        ),
    ]
    result = analyze_packets(packets)
    assert len(result) == 1
    assert "No timely matching request" in result.iloc[0]["finding"]
