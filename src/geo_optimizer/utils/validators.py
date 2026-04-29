"""
Input validators for GEO Optimizer.

Checks URLs (anti-SSRF) and file paths (anti-path-traversal)
before performing network or filesystem operations.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private/reserved networks to block (RFC 1918, loopback, link-local, cloud metadata)
# Fix #80: explicit IPv6 ranges to prevent SSRF bypass via IPv6 addresses.
# Note: ::ffff:0:0/96 covers all ::ffff:* sub-ranges (IPv4-mapped),
# but ranges are listed explicitly for clarity and security auditing.
_BLOCKED_NETWORKS = [
    # ── IPv4 ────────────────────────────────────────────────────────────────────
    ipaddress.ip_network("0.0.0.0/8"),  # "this network" RFC 1122
    ipaddress.ip_network("127.0.0.0/8"),  # loopback IPv4
    ipaddress.ip_network("10.0.0.0/8"),  # private RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # private RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),  # private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT RFC 6598
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmark testing RFC 2544
    ipaddress.ip_network("169.254.0.0/16"),  # link-local (AWS/GCP/Azure metadata)
    # ── IPv6 ────────────────────────────────────────────────────────────────────
    ipaddress.ip_network("::1/128"),  # loopback IPv6
    ipaddress.ip_network("fc00::/7"),  # unique local (ULA) RFC 4193: fc00:: - fdff::
    ipaddress.ip_network("fe80::/10"),  # link-local IPv6 RFC 4291
    # IPv4-mapped IPv6 (::ffff:0:0/96 covers all sub-ranges, listed explicitly for clarity)
    ipaddress.ip_network("::ffff:0:0/96"),  # entire IPv4-mapped space (common bypass)
    ipaddress.ip_network("::ffff:127.0.0.0/104"),  # loopback IPv4-mapped
    ipaddress.ip_network("::ffff:10.0.0.0/104"),  # RFC 1918 private IPv4-mapped
    ipaddress.ip_network("::ffff:172.16.0.0/108"),  # RFC 1918 private IPv4-mapped
    ipaddress.ip_network("::ffff:192.168.0.0/112"),  # RFC 1918 private IPv4-mapped
]

_ALLOWED_SCHEMES = {"https", "http"}

# Known internal hostnames
_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "169.254.169.254",
}


def _env_flag_enabled(name: str) -> bool:
    """Return True if an environment flag is enabled."""
    value = os.environ.get(name, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _parse_csv_env(name: str) -> list[str]:
    """Parse a comma-separated environment variable into normalized tokens."""
    raw = os.environ.get(name, "")
    return [token.strip().lower().strip(".") for token in raw.split(",") if token.strip()]


def _hostname_matches_allowed_domains(hostname: str, allowed_domains: list[str]) -> bool:
    """Return True if hostname matches an allowed domain (exact or subdomain)."""
    host = hostname.lower().strip(".")
    for domain in allowed_domains:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _is_private_ip_explicitly_allowed(hostname: str, ip_str: str) -> bool:
    """Allow private/reserved IP only with explicit env-based allowlists."""
    if not _env_flag_enabled("GEO_ALLOW_PRIVATE_NET"):
        return False

    allowed_domains = _parse_csv_env("GEO_PRIVATE_ALLOW_DOMAINS")
    if not allowed_domains:
        return False
    if not _hostname_matches_allowed_domains(hostname, allowed_domains):
        return False

    # Optional CIDR restriction: if omitted, any private IP for allowed domains is accepted.
    allowed_cidrs = _parse_csv_env("GEO_PRIVATE_ALLOW_CIDRS")
    if not allowed_cidrs:
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for cidr in allowed_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Invalid CIDR in GEO_PRIVATE_ALLOW_CIDRS: %s", cidr)
            continue
        if ip_obj in network:
            return True
    return False


def _is_ip_blocked(ip_obj) -> bool:
    """Check whether an IP is private/reserved using Python's standard APIs.

    Fallback to catch networks not in the explicit blocklist.
    """
    return bool(
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast
    )


def _validate_url_structure(url: str) -> tuple[bool, str | None, str | None]:
    """Validate the URL structure (scheme, hostname, credentials).

    Returns:
        (valid, error, hostname) — hostname is None if invalid.
    """
    parsed = urlparse(url)

    # 1. Check scheme
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, f"Scheme not allowed: '{parsed.scheme}'. Only http/https.", None

    # 2. Extract hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Missing or invalid hostname.", None

    # 3. Block known internal hostnames
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return False, f"Host not allowed: '{hostname}'.", None

    # 4. Block URLs with embedded credentials (user:pass@host)
    if "@" in (parsed.netloc or ""):
        return False, "URLs with embedded credentials not allowed.", None

    return True, None, hostname


def _check_ip_blocked(ip_str: str) -> tuple[bool, str | None]:
    """Check whether a single IP address is in a blocked network.

    Returns:
        (blocked, error_message) — blocked=True if the IP should be blocked.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        # Non-parseable IP: skip silently
        return False, None

    # Check explicit blocklist
    for network in _BLOCKED_NETWORKS:
        if ip_obj in network:
            # Fix M-3: generic message to user, detailed log at DEBUG only
            logger.debug("Blocked IP %s in network %s", ip_str, network)
            return True, "URL points to a non-public address."

    # Fallback: catch private networks not in the explicit blocklist
    if _is_ip_blocked(ip_obj):
        logger.debug("Blocked IP %s (private/reserved per stdlib)", ip_str)
        return True, "URL points to a non-public address."

    return False, None


def resolve_and_validate_url(url: str) -> tuple[bool, str | None, list[str]]:
    """Validate the URL anti-SSRF and return the list of resolved IPs.

    Resolves DNS ONCE and returns the validated IPs.
    This prevents TOCTOU DNS rebinding attacks: the caller must
    use these IPs for the actual connection without a second DNS resolution.

    Returns:
        (valid, error, resolved_ip_list)
        - resolved_ip_list is empty if DNS is unresolvable or URL is invalid.
    """
    # Validate URL structure
    ok, err, hostname = _validate_url_structure(url)
    if not ok:
        return False, err, []

    # Resolve DNS and verify that every resolved IP is public
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # DNS unresolvable → reject to prevent TOCTOU (#427):
        # if the domain becomes resolvable to a private IP after validation,
        # an unpinned session would allow SSRF
        return False, "DNS resolution failed: hostname not resolvable", []

    ip_validi = []
    for _, _, _, _, sockaddr in infos:
        ip_str = str(sockaddr[0])
        bloccato, msg = _check_ip_blocked(ip_str)
        if bloccato:
            if _is_private_ip_explicitly_allowed(hostname, ip_str):
                logger.debug("Private IP %s allowed for hostname %s via env allowlist", ip_str, hostname)
                ip_validi.append(ip_str)
                continue
            # Fix M-3: do not include resolved IP in user-facing error message
            logger.debug("SSRF blocked: %s resolved to %s", hostname, ip_str)
            return (
                False,
                "URL points to a non-public address.",
                [],
            )
        ip_validi.append(ip_str)

    return True, None, ip_validi


def validate_public_url(url: str) -> tuple[bool, str | None]:
    """
    Verify that the URL points to a public host, not internal networks.

    Prevents SSRF attacks by blocking:
    - Private IPs (RFC 1918), loopback, link-local
    - Cloud metadata endpoints (169.254.169.254)
    - Disallowed schemes (file://, ftp://, etc.)
    - Known internal hostnames (localhost, metadata)

    Returns:
        (True, None) if safe, (False, error_message) otherwise.
    """
    ok, err, _ips = resolve_and_validate_url(url)
    return ok, err


def validate_safe_path(
    file_path: str,
    allowed_extensions: set[str] | None = None,
    must_exist: bool = False,
    base_dir: str | Path | None = None,
) -> tuple[bool, str | None]:
    """
    Verify that a file path is safe.

    Resolves symlinks and path traversal, checks the extension,
    and optionally verifies the resolved path stays within *base_dir*.

    Args:
        file_path: Path to validate.
        allowed_extensions: Set of allowed extensions (e.g. {".html", ".htm"}).
        must_exist: If True, verifies that the file exists.
        base_dir: If provided, the resolved path must be inside this directory.

    Returns:
        (True, None) if safe, (False, error_message) otherwise.
    """
    try:
        resolved = Path(file_path).resolve()
    except (OSError, ValueError) as e:
        return False, f"Invalid path: {e}"

    if base_dir is not None:
        base_resolved = Path(base_dir).resolve()
        if not str(resolved).startswith(str(base_resolved) + os.sep) and resolved != base_resolved:
            return False, f"Path escapes base directory: {resolved}"

    if must_exist and not resolved.exists():
        return False, f"File not found: {resolved}"

    if must_exist and not resolved.is_file():
        return False, f"Not a file: {resolved}"

    if allowed_extensions and resolved.suffix.lower() not in allowed_extensions:
        return False, (f"Extension not allowed: '{resolved.suffix}'. Allowed: {', '.join(sorted(allowed_extensions))}")

    return True, None


def url_belongs_to_domain(url: str, domain: str) -> bool:
    """
    Verify exact domain membership, without substring matching.

    Handles legitimate subdomains (e.g. blog.example.com for example.com).
    Blocks URLs with embedded credentials (@).

    Args:
        url: Full URL to check.
        domain: Reference domain (e.g. "example.com").

    Returns:
        True if the URL belongs to the domain.
    """
    parsed = urlparse(url)
    netloc = parsed.netloc

    # Block URLs with embedded credentials
    if "@" in netloc:
        return False

    # Remove port if present
    hostname = netloc.split(":")[0].lower()
    domain_lower = domain.lower()

    # Exact match or legitimate subdomain
    return hostname == domain_lower or hostname.endswith("." + domain_lower)
