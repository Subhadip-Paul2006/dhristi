# Drishti v0.1 — live DNS, TLS and HTTP checks | 11-Jul-2026
"""Live connection checks: DNS, TLS certificate, HTTP status + redirect chain.

Every outbound call is wrapped so a blocked network or a dead host degrades to a
clear "unreachable" (return None) instead of crashing or fabricating a value.
These functions are the seams the tests monkeypatch to stay fully offline.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.config import get_settings
from app.services.urltrust.checks import registrable_domain

# Response body cap for http_probe (bytes) and the max redirect hops it will
# follow — each hop is re-validated against _is_safe_ip before being fetched.
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_REDIRECTS = 5

# Shared, bounded pool for the timeout-wrapped getaddrinfo calls. A per-call
# ThreadPoolExecutor with shutdown(wait=False) leaks a live worker for every
# stalled resolution; a single module-level pool caps that to `max_workers`
# threads total no matter how many probes stall.
_DNS_EXECUTOR = ThreadPoolExecutor(max_workers=16, thread_name_prefix="urltrust-dns")


def _is_safe_ip(ip: str) -> bool:
    """Reject anything that isn't a routable public address — private,
    loopback, link-local (covers the 169.254.169.254 cloud metadata address),
    reserved, and multicast ranges are all blocked. Used to stop SSRF into the
    internal network before any TCP/TLS/HTTP connection is made."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _resolve_ips(host: str, timeout: float) -> list[str]:
    """getaddrinfo has no timeout of its own; run it on the shared worker pool
    so a stalling DNS server can't hang the caller past `timeout`. On timeout
    the future is cancelled and the (bounded) pool reclaims the worker once the
    OS call returns — no per-call thread is leaked."""
    future = _DNS_EXECUTOR.submit(socket.getaddrinfo, host, None)
    try:
        infos = future.result(timeout=timeout)
    finally:
        future.cancel()
    return sorted({info[4][0] for info in infos})


def _safe_ips(host: str, timeout: float) -> list[str] | None:
    """Resolve `host` and return its IPs only if every one of them is safe to
    connect to. None on resolution failure/timeout or if any IP is blocked."""
    try:
        ips = _resolve_ips(host, timeout)
    except Exception:
        return None
    if not ips or not all(_is_safe_ip(ip) for ip in ips):
        return None
    return ips


def resolve_dns(host: str) -> bool | None:
    """True if the host resolves and EVERY resolved IP is routable (safe), False
    if it definitively does not exist (NXDOMAIN), None if resolution could not be
    attempted or ANY resolved IP is private/loopback/reserved (which the analyzer
    refuses to contact — so DNS must not report a clean PASS for it). This mirrors
    the strict all-public rule used by _safe_ips for TLS/HTTP."""
    timeout = get_settings().urltrust_timeout_seconds
    try:
        ips = _resolve_ips(host, timeout)
    except socket.gaierror as exc:
        no_name = {getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5)}
        return False if exc.errno in no_name else None
    except Exception:
        return None
    if not ips:
        return None
    # resolves to ANY blocked/private IP → treat as not-a-pass (consistent with
    # TLS/HTTP, which use _safe_ips' all-public rule and report unreachable for
    # the same host). Only an all-public resolution is a clean PASS.
    return True if all(_is_safe_ip(ip) for ip in ips) else None


def inspect_tls(host: str, port: int = 443) -> dict | None:
    """Return {valid, issuer, expires} for the peer certificate.

    valid=True  → certificate verified against the system trust store.
    valid=False → connected but the certificate is invalid/expired/mismatched.
    None        → could not connect at all (unreachable), NOT a trust judgement.
    """
    timeout = get_settings().urltrust_timeout_seconds
    ips = _safe_ips(host, timeout)
    if ips is None:
        return None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ips[0], port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        return {
            "valid": True,
            "issuer": _cert_issuer(cert),
            "expires": _cert_not_after(cert),
        }
    except ssl.SSLCertVerificationError as exc:
        # Reached the host but the certificate is not trustworthy.
        return {"valid": False, "issuer": None, "expires": None, "error": _short(str(exc))}
    except (socket.timeout, TimeoutError):
        return None
    except (ssl.SSLError, OSError):
        # includes connection refused / reset / DNS-at-connect / blocked outbound
        return None
    except Exception:
        return None


def http_probe(url: str) -> dict | None:
    """Follow redirects and report status + chain. None if unreachable.

    Redirects are followed manually (not via httpx's follow_redirects) so
    each hop's host can be re-validated against _safe_ips before it is
    fetched — otherwise a URL that looks external at submission time could
    302 the live request into the internal network.

    Crucially, each hop is fetched against the *validated IP itself* rather than
    the hostname: httpx (via httpcore) would otherwise re-run getaddrinfo at
    connect time, so a DNS-rebind that flips the record between validation and
    the socket connect (TOCTOU) could still land on an internal IP. We pin the
    connection to the IP we checked and restore the original hostname for the
    Host header and TLS SNI / certificate verification via the `sni_hostname`
    extension, so trust judgements still key off the real hostname."""
    timeout = get_settings().urltrust_timeout_seconds
    try:
        import httpx
    except Exception:
        return None

    chain: list[str] = []
    current = url  # logical (hostname-based) URL for this hop
    status: int | None = None
    final_url = url
    try:
        with httpx.Client(
            follow_redirects=False, timeout=timeout,
            headers={"User-Agent": "Drishti-URLTrust/1.0 (+defensive-scan)"},
        ) as client:
            for _ in range(_MAX_REDIRECTS + 1):
                url_obj = httpx.URL(current)
                host = url_obj.host or ""
                ips = _safe_ips(host, timeout)
                if ips is None:
                    return None
                # Pin the socket to the validated IP; keep the hostname for the
                # Host header and for SNI / cert verification so httpcore cannot
                # re-resolve the name to a different (internal) address.
                connect_url = url_obj.copy_with(host=ips[0])
                host_header = f"{host}:{url_obj.port}" if url_obj.port is not None else host
                with client.stream(
                    "GET", connect_url,
                    headers={"Host": host_header},
                    extensions={"sni_hostname": host},
                ) as resp:
                    _drain(resp)
                    status = resp.status_code
                    # Report the logical (hostname) URL, not the pinned-IP one.
                    final_url = current
                    chain.append(final_url)
                    if not resp.is_redirect:
                        break
                    location = resp.headers.get("location")
                    if not location:
                        break
                    # Resolve the redirect against the logical URL so relative
                    # Location headers don't inherit the pinned IP authority.
                    current = str(url_obj.join(location))
            else:
                return None  # too many redirect hops
    except Exception:
        return None

    try:
        origin = registrable_domain(httpx.URL(url).host or "")
        final = registrable_domain(httpx.URL(final_url).host or "")
        offsite = bool(origin) and bool(final) and origin != final
    except Exception:
        offsite = None
    return {
        "status": status,
        "final_url": final_url,
        "redirect_chain": chain,
        "redirects_offsite": offsite,
    }


def _drain(resp, limit: int = _MAX_RESPONSE_BYTES) -> None:
    """Read the streamed response body up to `limit` bytes so a probe target
    can't force the whole body into memory, then stop (the caller's `with`
    block closes the connection)."""
    total = 0
    for chunk in resp.iter_bytes():
        total += len(chunk)
        if total >= limit:
            break


def _cert_issuer(cert: dict | None) -> str | None:
    if not cert:
        return None
    fields = {k: v for tup in cert.get("issuer", ()) for (k, v) in tup}
    return fields.get("organizationName") or fields.get("commonName")


def _cert_not_after(cert: dict | None) -> str | None:
    if not cert or not cert.get("notAfter"):
        return None
    try:
        epoch = ssl.cert_time_to_seconds(cert["notAfter"])
        return datetime.fromtimestamp(epoch, tz=timezone.utc).date().isoformat()
    except (ValueError, TypeError):
        return None


def _short(msg: str, limit: int = 120) -> str:
    msg = " ".join(msg.split())
    return msg[:limit]
