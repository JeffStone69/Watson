"""TLS inspection using the normal handshake. No extra ports are probed."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class TlsInfo:
    ok: bool
    protocol: str | None = None
    not_after: datetime | None = None
    verified: bool = False
    hostname_ok: bool = True
    error: str | None = None


def _parse_not_after(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _not_after_from_der(der: bytes | None) -> datetime | None:
    if not der:
        return None
    decoder = getattr(ssl, "_ssl", None)
    decode = getattr(decoder, "_test_decode_cert", None) if decoder else None
    if decode is None:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der)
    handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    try:
        handle.write(pem)
        handle.close()
        decoded = decode(handle.name)
    except Exception:
        return None
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
    return _parse_not_after(decoded.get("notAfter") if isinstance(decoded, dict) else None)


def _plain_tls_error(exc: BaseException) -> str:
    """Return a fixed phrase. Certificate subjects can contain personal names."""
    text = str(exc).lower()
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in text:
        return "timed out"
    if isinstance(exc, ConnectionRefusedError) or "connection refused" in text or "actively refused" in text:
        return "connection refused"
    if "certificate" in text and "mismatch" in text:
        return "certificate name did not match"
    if "certificate" in text:
        return "certificate was rejected"
    return "TLS handshake failed"


def inspect_tls(host: str, port: int, timeout: float) -> TlsInfo:
    """Handshake with the host and read the certificate. Nothing else is scanned."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                protocol = secure.version()
                not_after = _parse_not_after(cert.get("notAfter") if cert else None)
                return TlsInfo(
                    ok=True,
                    protocol=protocol,
                    not_after=not_after,
                    verified=True,
                    hostname_ok=True,
                )
    except ssl.SSLCertVerificationError as exc:
        message = str(exc).lower()
        hostname_ok = "hostname mismatch" not in message
        unverified = _inspect_unverified(host, port, timeout)
        unverified.verified = False
        unverified.hostname_ok = hostname_ok
        if not unverified.ok:
            unverified.error = "certificate was rejected"
        return unverified
    except (ssl.SSLError, TimeoutError, socket.timeout, OSError) as exc:
        return TlsInfo(ok=False, verified=False, hostname_ok=True, error=_plain_tls_error(exc))


def _inspect_unverified(host: str, port: int, timeout: float) -> TlsInfo:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                protocol = secure.version()
                der = secure.getpeercert(binary_form=True)
                return TlsInfo(
                    ok=True,
                    protocol=protocol,
                    not_after=_not_after_from_der(der),
                    verified=False,
                    hostname_ok=True,
                )
    except (ssl.SSLError, TimeoutError, socket.timeout, OSError):
        return TlsInfo(ok=False, verified=False, error="certificate was rejected")
