"""URL 구조를 판정 없이 수치화한다."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from urllib.parse import parse_qsl, urlsplit


class URLFeatureExtractor:
    """고정 도메인 목록이나 위험 점수 없이 URL 구조 특징만 반환한다."""

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def extract(self, url: str) -> dict:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        labels = [label for label in hostname.split(".") if label]
        try:
            ipaddress.ip_address(hostname)
            host_is_ip = True
        except ValueError:
            host_is_ip = False

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        redirect_target_count = 0
        for _, value in query_pairs:
            candidate = value.strip().lower()
            if candidate.startswith(("http://", "https://", "//")):
                redirect_target_count += 1

        hostname_length = len(hostname)
        return {
            "scheme": parsed.scheme.lower(),
            "scheme_is_https": parsed.scheme.lower() == "https",
            "hostname": hostname,
            "host_is_ip": host_is_ip,
            "has_userinfo": parsed.username is not None or parsed.password is not None,
            "has_explicit_port": parsed.port is not None,
            "port": parsed.port,
            "uses_punycode": any(label.startswith("xn--") for label in labels),
            "hostname_label_count": len(labels),
            "hostname_length": hostname_length,
            "hostname_digit_ratio": sum(char.isdigit() for char in hostname) / max(hostname_length, 1),
            "hostname_hyphen_count": hostname.count("-"),
            "hostname_entropy": self._entropy(hostname),
            "url_length": len(url),
            "path_length": len(parsed.path),
            "path_segment_count": len([part for part in parsed.path.split("/") if part]),
            "query_length": len(parsed.query),
            "query_parameter_count": len(query_pairs),
            "fragment_length": len(parsed.fragment),
            "embedded_redirect_target_count": redirect_target_count,
        }


URL_NUMERIC_FEATURE_NAMES = (
    "scheme_is_https",
    "host_is_ip",
    "has_userinfo",
    "has_explicit_port",
    "uses_punycode",
    "hostname_label_count",
    "hostname_length",
    "hostname_digit_ratio",
    "hostname_hyphen_count",
    "hostname_entropy",
    "url_length",
    "path_length",
    "path_segment_count",
    "query_length",
    "query_parameter_count",
    "fragment_length",
    "embedded_redirect_target_count",
)


def numeric_url_features(url: str) -> dict[str, float]:
    observed = URLFeatureExtractor().extract(url)
    return {name: float(observed[name]) for name in URL_NUMERIC_FEATURE_NAMES}
