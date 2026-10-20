"""Protects the scanner itself.

A service that fetches user-supplied URLs can be abused to reach internal systems
(SSRF). Every host we connect to — including each redirect hop — goes through
`assert_safe_host` first.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

from . import config


class UnsafeTargetError(ValueError):
    pass


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTargetError("Enter a website address.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http:// and https:// addresses can be scanned.")
    if parts.username or parts.password:
        raise UnsafeTargetError("Remove the username/password from the address.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeTargetError("That doesn't look like a valid address.")
    try:
        port = parts.port
    except ValueError:
        raise UnsafeTargetError("Invalid port number.")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def is_private_address(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not addr.is_global or addr.is_multicast


async def resolve_host(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeTargetError(f"Couldn't find {host} — check the spelling.")
    return sorted({info[4][0] for info in infos})


async def assert_safe_host(host: str) -> list[str]:
    """Resolve `host` and refuse private/internal addresses. Returns the IPs."""
    ips = await resolve_host(host)
    # Link-local covers cloud metadata endpoints (169.254.169.254); never reachable, even in dev mode.
    if any(ipaddress.ip_address(ip).is_link_local for ip in ips):
        raise UnsafeTargetError(f"{host} points to a link-local address, which we never scan.")
    if not config.ALLOW_PRIVATE_TARGETS and any(is_private_address(ip) for ip in ips):
        raise UnsafeTargetError(f"{host} points to a private network address, which we don't scan.")
    return ips


async def is_local_dev_target(host: str) -> bool:
    """True when dev mode is on and the host is on this machine / private network."""
    if not config.ALLOW_PRIVATE_TARGETS:
        return False
    try:
        ips = await resolve_host(host)
    except UnsafeTargetError:
        return False
    return all(is_private_address(ip) for ip in ips)
