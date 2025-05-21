from collections import defaultdict
from datetime import datetime, timedelta, UTC
from typing import Any

ip_hits: dict[str, Any] = defaultdict(list)
path_hits: dict[str, Any] = defaultdict(set)


def is_suspicious(ip: str, path: str, headers: dict) -> str:
    now = datetime.now(UTC)
    ip_hits[ip] = [t for t in ip_hits[ip] if now - t < timedelta(seconds=3)]
    ip_hits[ip].append(now)

    path_hits[ip].add(path)

    if len(ip_hits[ip]) > 10:
        return "Rate Limit Exceeded"
    if len(path_hits[ip]) > 20:
        return "Brute Force Detected"
    if len(headers) > 15:
        return "Header Flood Detected"
    return ""
