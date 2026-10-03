"""Shared utility helpers."""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional


def human_bytes(value: int) -> str:
    """Convert bytes to a human-readable unit."""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{value} B"


def resolve_hostname(host: str) -> Optional[str]:
    """Resolve hostname into an IPv4/IPv6 address."""
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def is_private_or_loopback(ip: str) -> bool:
    """Only permit local-network diagnostic testing targets."""
    try:
        parsed = ipaddress.ip_address(ip)
        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
        )
    except ValueError:
        return False
