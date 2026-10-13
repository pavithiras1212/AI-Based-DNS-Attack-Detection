
"""Feature extraction utilities for DNS traffic."""

import math


def domain_length(domain: str) -> int:
    """Return the length of a domain name."""
    return len(domain.strip().rstrip("."))


def subdomain_count(domain: str) -> int:
    """Count the labels preceding the registered-domain portion.

    This is a simple label-counting helper, not a complete
    public-suffix-aware domain parser.
    """
    cleaned = domain.strip().strip(".")
    labels = cleaned.split(".") if cleaned else []

    return max(0, len(labels) - 2)


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0

    entropy = 0.0
    length = len(text)

    for character in set(text):
        probability = text.count(character) / length
        entropy -= probability * math.log2(probability)

    return entropy
