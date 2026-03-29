
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="QRIE Scanner API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Request model
# -----------------------------
class ScanRequest(BaseModel):
    targets: list[str]
    ports: list[int] = [443]
    tls_timeout: float = 6.0
    resolve_timeout: float = 5.0
    enumerate_subdomains: bool = False
    output_dir: str = "."
    write_files: bool = True


# -----------------------------
# TLS helpers
# -----------------------------
TLS_VERSION_MAP = {
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

TLS_PROBE_ORDER = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

TLS_VERSION_CONSTS = {
    "TLSv1.0": (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    "TLSv1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
}

PFS_KEX = {"ECDHE", "DHE", "EDH"}

WEAK_CIPHER_MARKERS = (
    "NULL",
    "RC4",
    "DES",
    "3DES",
    "EXPORT",
    "MD5",
    "SHA1",
    "ANON",
)

CMS_HINTS = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "magento": "Magento",
    "shopify": "Shopify",
    "prestashop": "PrestaShop",
    "typo3": "TYPO3",
    "ghost": "Ghost",
}

TECH_HINTS = {
    "nginx": "Nginx",
    "apache": "Apache",
    "openresty": "OpenResty",
    "caddy": "Caddy",
    "lighttpd": "Lighttpd",
    "iis": "Microsoft IIS",
    "microsoft-iis": "Microsoft IIS",
    "gunicorn": "Gunicorn",
    "uwsgi": "uWSGI",
    "uvicorn": "Uvicorn",
    "tomcat": "Apache Tomcat",
    "jetty": "Jetty",
    "envoy": "Envoy",
    "cloudflare": "Cloudflare",
    "varnish": "Varnish",
    "express": "Express",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "php": "PHP",
    "asp.net": "ASP.NET",
    "django": "Django",
    "laravel": "Laravel",
    "spring": "Spring",
}

OS_HINTS = {
    "windows": "Windows",
    "microsoft iis": "Windows",
    "asp.net": "Windows",
    "ubuntu": "Ubuntu / Linux",
    "debian": "Debian / Linux",
    "centos": "CentOS / Linux",
    "red hat": "Red Hat / Linux",
    "fedora": "Fedora / Linux",
    "alpine": "Alpine / Linux",
    "linux": "Linux / Unix",
    "unix": "Unix",
    "freebsd": "FreeBSD",
    "openbsd": "OpenBSD",
    "mac os": "macOS",
    "darwin": "macOS",
}

# -----------------------------
# Generic helpers
# -----------------------------
def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def unique_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    out: list[str] = []
    for item in items:
        key = normalize_host(item)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def resolve_host(host: str, timeout: float = 5.0) -> str | None:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


def safe_get_text(url: str, timeout: float = 5.0, https_context: ssl.SSLContext | None = None) -> tuple[int | None, dict, str]:
    headers = {"User-Agent": "Mozilla/5.0"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=https_context) as res:
            status = getattr(res, "status", None)
            hdrs = dict(res.getheaders())
            body_bytes = res.read(4096)
            body = body_bytes.decode("utf-8", errors="ignore")
            return status, hdrs, body
    except urllib.error.HTTPError as e:
        try:
            hdrs = dict(e.headers.items()) if e.headers else {}
        except Exception:
            hdrs = {}
        body = ""
        try:
            body = e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return e.code, hdrs, body
    except Exception:
        return None, {}, ""


# -----------------------------
# crt.sh enumeration
# -----------------------------
def enumerate_from_crtsh(domain: str) -> set[str]:
    domain = normalize_host(domain)
    if is_ip_address(domain):
        return set()

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 200:
                return set()

            payload = response.read().decode("utf-8", errors="ignore")
            data = json.loads(payload)

            for entry in data:
                name_value = entry.get("name_value", "")
                for raw_name in name_value.split("\n"):
                    name = normalize_host(raw_name)
                    if not name or name.startswith("*."):
                        continue
                    if name == domain or name.endswith("." + domain):
                        if re.fullmatch(r"[a-z0-9.-]+", name):
                            subdomains.add(name)
    except Exception:
        pass

    return subdomains


# -----------------------------
# TLS probing
# -----------------------------
def probe_single_tls_version(host: str, port: int, tls_ver: str, timeout: float) -> tuple[bool, dict]:
    bounds = TLS_VERSION_CONSTS.get(tls_ver)
    if bounds is None:
        return False, {}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.minimum_version = bounds[0]
        ctx.maximum_version = bounds[1]
    except Exception:
        return False, {}

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            t0 = time.monotonic()
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                latency_ms = round((time.monotonic() - t0) * 1000, 1)
                cipher_tuple = tls_sock.cipher()
                negotiated = tls_sock.version()
                der_cert = tls_sock.getpeercert(binary_form=True)
                return True, {
                    "negotiated_version": negotiated,
                    "cipher_tuple": cipher_tuple,
                    "latency_ms": latency_ms,
                    "der_cert": der_cert,
                }
    except Exception:
        return False, {}


def parse_cipher(cipher_tuple: tuple | None) -> dict:
    if not cipher_tuple:
        return {
            "cipher_suite": None,
            "key_exchange": None,
            "authentication": None,
            "encryption": None,
            "hash_algo": None,
            "pfs": "Unknown",
        }

    name = cipher_tuple[0]

    # TLS 1.3 cipher suites use underscore format (e.g. TLS_AES_128_GCM_SHA256).
    # The KEX is not encoded in the name; TLS 1.3 mandates ECDHE for every
    # handshake, so PFS is always guaranteed — never parse these with TLS 1.2 logic.
    if name.startswith("TLS_"):
        return {
            "cipher_suite": name,
            "key_exchange": "ECDHE",   # TLS 1.3 always uses ephemeral key exchange
            "authentication": None,
            "encryption": None,
            "hash_algo": None,
            "pfs": "Yes",
        }

    # TLS 1.2 and earlier: parse KEX from dash-delimited cipher name
    parts = name.split("-")

    kex = parts[0] if parts else None
    auth = parts[1] if len(parts) > 1 else None
    enc = "-".join(parts[2:-1]) if len(parts) > 3 else (parts[2] if len(parts) > 2 else None)
    mac = parts[-1] if parts else None

    pfs = "Yes" if kex in PFS_KEX else ("No" if kex else "Unknown")

    return {
        "cipher_suite": name,
        "key_exchange": kex,
        "authentication": auth,
        "encryption": enc,
        "hash_algo": mac,
        "pfs": pfs,
    }


# -----------------------------
# Certificate extraction
# -----------------------------
def extract_cert_info(der_cert: bytes | None) -> dict:
    if not der_cert:
        return {
            "public_key_algo": None,
            "key_size_bits": None,
            "signature_algo": None,
            "issuer_ca": None,
            "not_before": None,
            "not_after": None,
            "oid_reference": None,
            "subject_cn": None,
        }

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

        cert = x509.load_der_x509_certificate(der_cert)
        pub_key = cert.public_key()
        sig_algo = cert.signature_algorithm_oid.dotted_string

        if isinstance(pub_key, rsa.RSAPublicKey):
            pk_algo = "RSA"
            key_bits = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pk_algo = "EC"
            key_bits = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pk_algo = "DSA"
            key_bits = pub_key.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pk_algo = type(pub_key).__name__.replace("PublicKey", "")
            key_bits = 256 if "25519" in pk_algo else 448
        else:
            pk_algo = type(pub_key).__name__
            key_bits = None

        try:
            sig_name = cert.signature_hash_algorithm.name + "With" + pk_algo
        except Exception:
            sig_name = sig_algo

        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            subject_cn = cn[0].value if cn else None
        except Exception:
            subject_cn = None

        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            issuer_ca = f"CN={issuer_cn[0].value}" if issuer_cn else str(cert.issuer)
        except Exception:
            issuer_ca = str(cert.issuer)

        try:
            not_before = cert.not_valid_before_utc.isoformat()
            not_after = cert.not_valid_after_utc.isoformat()
        except Exception:
            not_before = None
            not_after = None

        return {
            "public_key_algo": pk_algo,
            "key_size_bits": key_bits,
            "signature_algo": sig_name,
            "issuer_ca": issuer_ca,
            "not_before": not_before,
            "not_after": not_after,
            "oid_reference": sig_algo,
            "subject_cn": subject_cn,
        }
    except ImportError:
        return {
            "public_key_algo": "RSA",
            "key_size_bits": None,
            "signature_algo": None,
            "issuer_ca": None,
            "not_before": None,
            "not_after": None,
            "oid_reference": None,
            "subject_cn": None,
        }
    except Exception:
        return {
            "public_key_algo": None,
            "key_size_bits": None,
            "signature_algo": None,
            "issuer_ca": None,
            "not_before": None,
            "not_after": None,
            "oid_reference": None,
            "subject_cn": None,
        }


# -----------------------------
# HTTP / service fingerprinting
# -----------------------------
def extract_software_hints(headers: dict[str, str], body: str) -> dict:
    normalized_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    header_blob = " ".join(f"{k}: {v}" for k, v in normalized_headers.items()).lower()
    body_blob = (body or "").lower()

    server = normalized_headers.get("server")
    powered_by = normalized_headers.get("x-powered-by")
    technology_hints: list[str] = []
    software_versions: list[str] = []

    def add_hint(label: str) -> None:
        if label not in technology_hints:
            technology_hints.append(label)

    def add_version(text: str) -> None:
        if text not in software_versions:
            software_versions.append(text)

    if server:
        add_hint(server)

        m = re.search(r"([a-zA-Z0-9._+-]+)[ /]?([0-9][a-zA-Z0-9._+-]*)?", server)
        if m and m.group(1):
            vendor = m.group(1)
            version = m.group(2)
            if version:
                add_version(f"{vendor}/{version}")
            else:
                add_version(vendor)

    if powered_by:
        add_hint(powered_by)
        m = re.search(r"([A-Za-z0-9._+-]+)[ /]?([0-9][A-Za-z0-9._+-]*)?", powered_by)
        if m and m.group(1):
            if m.group(2):
                add_version(f"{m.group(1)}/{m.group(2)}")
            else:
                add_version(m.group(1))

    for needle, label in TECH_HINTS.items():
        if needle in header_blob or needle in body_blob:
            add_hint(label)

    for needle, label in CMS_HINTS.items():
        if needle in header_blob or needle in body_blob:
            add_hint(label)

    for key, value in normalized_headers.items():
        if key in {"x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-drupal-cache"}:
            add_hint(f"{key}: {value}")
            if value:
                add_version(f"{key}: {value}")

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    page_title = title_match.group(1).strip() if title_match else None

    return {
        "page_title": page_title,
        "server_header": server,
        "x_powered_by": powered_by,
        "technology_hints": technology_hints,
        "software_versions": software_versions,
    }


def infer_os(server_header: str | None, powered_by: str | None, headers: dict[str, str], body: str) -> dict:
    blobs = " ".join(
        [
            server_header or "",
            powered_by or "",
            " ".join(f"{k}: {v}" for k, v in headers.items()),
            body[:2048],
        ]
    ).lower()

    inferred = "Unknown"
    confidence = "low"

    for needle, label in OS_HINTS.items():
        if needle in blobs:
            inferred = label
            confidence = "medium"
            break

    if inferred == "Unknown":
        if any(x in blobs for x in ["nginx", "apache", "openresty", "caddy", "gunicorn", "uvicorn", "wsgi", "uwsgi"]):
            inferred = "Linux / Unix likely"
            confidence = "low"

    version_hints: list[str] = []
    for pat in [
        r"\bubuntu\s+([0-9][0-9.]+)\b",
        r"\bdebian\s+([0-9][0-9.]+)\b",
        r"\bcentos\s+([0-9][0-9.]+)\b",
        r"\bred hat\s+([0-9][0-9.]+)\b",
        r"\balpine\s+([0-9][0-9.]+)\b",
        r"\bwindows\s+([0-9a-zA-Z ._-]+)\b",
        r"\bmacos\s+([0-9a-zA-Z ._-]+)\b",
    ]:
        for match in re.findall(pat, blobs, flags=re.IGNORECASE):
            if isinstance(match, tuple):
                value = " ".join(match).strip()
            else:
                value = str(match).strip()
            if value and value not in version_hints:
                version_hints.append(value)

    return {
        "os_guess": inferred,
        "confidence": confidence,
        "version_hints": version_hints,
    }


def fingerprint_http(host: str, port: int, timeout: float = 5.0, tls_supported: bool = False) -> dict:
    host = normalize_host(host)

    candidates: list[tuple[str, bool]] = []
    if port == 443 or tls_supported:
        candidates.append((f"https://{host}:{port}", True))
    candidates.append((f"http://{host}:{port}", False))

    for url, is_https in candidates:
        ctx = None
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        status, headers, body = safe_get_text(url, timeout=timeout, https_context=ctx)
        if status is None and not headers and not body:
            continue

        hints = extract_software_hints(headers, body)
        os_info = infer_os(
            hints.get("server_header"),
            hints.get("x_powered_by"),
            headers,
            body,
        )

        return {
            "scheme": urlparse(url).scheme,
            "url": url,
            "status": status,
            "headers": headers,
            "page_title": hints.get("page_title"),
            "server_header": hints.get("server_header"),
            "x_powered_by": hints.get("x_powered_by"),
            "technology_hints": hints.get("technology_hints", []),
            "software_versions": hints.get("software_versions", []),
            "os_guess": os_info.get("os_guess"),
            "os_confidence": os_info.get("confidence"),
            "os_version_hints": os_info.get("version_hints", []),
            "body_snippet": body[:512] if body else "",
        }

    return {
        "scheme": None,
        "url": None,
        "status": None,
        "headers": {},
        "page_title": None,
        "server_header": None,
        "x_powered_by": None,
        "technology_hints": [],
        "software_versions": [],
        "os_guess": "Unknown",
        "os_confidence": "low",
        "os_version_hints": [],
        "body_snippet": "",
    }


# -----------------------------
# Risk labels
# -----------------------------
def pqc_label(key_algo: str | None, key_bits: int | None, cipher: str | None) -> str:
    if not key_algo:
        return "Unknown"
    algo = key_algo.upper()
    if algo in ("CRYSTALS-KYBER", "CRYSTALS-DILITHIUM", "SPHINCS+", "FALCON"):
        return "PQC-Ready"
    if algo == "RSA":
        if key_bits and key_bits >= 4096:
            return "Migration-Candidate"
        return "Quantum-Vulnerable"
    if algo in ("ECDSA", "EC"):
        return "Quantum-Vulnerable"
    return "Unknown"


def is_valid_crypto_record(record: dict) -> bool:
    return (
        record.get("TLS Supported") is True
        and record.get("Scan Status") == "ok"
        and record.get("Cipher Suite") is not None
    )


def is_shadow_crypto_record(record: dict) -> bool:
    if not is_valid_crypto_record(record):
        return False

    tls_version = str(record.get("TLS Version") or "")
    cipher = str(record.get("Cipher Suite") or "").upper()
    pfs = str(record.get("PFS Status") or "Unknown")
    key_bits = record.get("Key Size (Bits)")

    if tls_version in {"TLSv1.0", "TLSv1.1"}:
        return True
    if pfs != "Yes":
        return True
    if any(marker in cipher for marker in WEAK_CIPHER_MARKERS):
        return True
    if isinstance(key_bits, int) and key_bits and key_bits < 2048:
        return True

    return False


def build_cbom_record(
    host: str,
    port: int,
    ip: str | None,
    probe_results: dict[str, tuple[bool, dict]],
    tls_timeout: float = 6.0,
) -> dict:
    supported_versions = [v for v in TLS_PROBE_ORDER if probe_results.get(v, (False,))[0]]
    tls_supported = len(supported_versions) > 0

    http_fp = fingerprint_http(host, port, timeout=tls_timeout, tls_supported=tls_supported)

    if not tls_supported:
        return {
            "Asset ID": str(uuid.uuid4()),
            "Asset": host,
            "IP Address": ip,
            "Port": port,
            "TLS Supported": False,
            "Supported TLS Versions": [],
            "Minimum Supported TLS": None,
            "Maximum Supported TLS": None,
            "TLS Version": None,
            "Cipher Suite": None,
            "Key Exchange Algorithm": None,
            "Authentication Algorithm": None,
            "Encryption Algorithm": None,
            "Hash Algorithm": None,
            "Handshake Latency": None,
            "Public Key Algorithm": None,
            "Key Size (Bits)": None,
            "PFS Status": "Unknown",
            "OID Reference": None,
            "NIST PQC Readiness Label": "Unknown",
            "Scan Status": "error",
            "Error": "No TLS version successfully negotiated",
            "Certificate Validity (Not Before/After)": {"Not Before": None, "Not After": None},
            "Signature Algorithm": None,
            "Issuer CA": None,
            "Subject CN": None,
            "HTTP Scheme": http_fp.get("scheme"),
            "HTTP URL": http_fp.get("url"),
            "HTTP Status": http_fp.get("status"),
            "Web Server": http_fp.get("server_header"),
            "X-Powered-By": http_fp.get("x_powered_by"),
            "Technology Hints": http_fp.get("technology_hints", []),
            "Software Versions": http_fp.get("software_versions", []),
            "Detected OS": http_fp.get("os_guess"),
            "OS Confidence": http_fp.get("os_confidence"),
            "OS Version Hints": http_fp.get("os_version_hints", []),
            "Response Headers": http_fp.get("headers", {}),
            "Page Title": http_fp.get("page_title"),
            "Body Snippet": http_fp.get("body_snippet"),
        }

    best_ver = supported_versions[-1]
    _, best_md = probe_results[best_ver]

    cipher_info = parse_cipher(best_md.get("cipher_tuple"))
    cert_info = extract_cert_info(best_md.get("der_cert"))

    pk_algo = cert_info["public_key_algo"]
    key_bits = cert_info["key_size_bits"]

    return {
        "Asset ID": str(uuid.uuid4()),
        "Asset": host,
        "IP Address": ip or "—",
        "Port": port,
        "TLS Supported": True,
        "Supported TLS Versions": supported_versions,
        "Minimum Supported TLS": supported_versions[0],
        "Maximum Supported TLS": supported_versions[-1],
        "TLS Version": best_ver,
        "Cipher Suite": cipher_info["cipher_suite"],
        "Key Exchange Algorithm": cipher_info["key_exchange"],
        "Authentication Algorithm": cipher_info["authentication"],
        "Encryption Algorithm": cipher_info["encryption"],
        "Hash Algorithm": cipher_info["hash_algo"],
        "Handshake Latency": best_md.get("latency_ms"),
        "Public Key Algorithm": pk_algo,
        "Key Size (Bits)": key_bits,
        "PFS Status": cipher_info["pfs"],
        "OID Reference": cert_info["oid_reference"],
        "NIST PQC Readiness Label": pqc_label(pk_algo, key_bits, cipher_info["cipher_suite"]),
        "Scan Status": "ok",
        "Error": None,
        "Certificate Validity (Not Before/After)": {
            "Not Before": cert_info["not_before"],
            "Not After": cert_info["not_after"],
        },
        "Signature Algorithm": cert_info["signature_algo"],
        "Issuer CA": cert_info["issuer_ca"],
        "Subject CN": cert_info["subject_cn"],
        "HTTP Scheme": http_fp.get("scheme"),
        "HTTP URL": http_fp.get("url"),
        "HTTP Status": http_fp.get("status"),
        "Web Server": http_fp.get("server_header"),
        "X-Powered-By": http_fp.get("x_powered_by"),
        "Technology Hints": http_fp.get("technology_hints", []),
        "Software Versions": http_fp.get("software_versions", []),
        "Detected OS": http_fp.get("os_guess"),
        "OS Confidence": http_fp.get("os_confidence"),
        "OS Version Hints": http_fp.get("os_version_hints", []),
        "Response Headers": http_fp.get("headers", {}),
        "Page Title": http_fp.get("page_title"),
        "Body Snippet": http_fp.get("body_snippet"),
    }


def build_shadow_crypto_record(record: dict) -> dict:
    cipher = str(record.get("Cipher Suite") or "")
    reasons: list[str] = []

    tls_version = str(record.get("TLS Version") or "")
    if tls_version in {"TLSv1.0", "TLSv1.1"}:
        reasons.append(f"Deprecated TLS version: {tls_version}")

    pfs = str(record.get("PFS Status") or "Unknown")
    if pfs != "Yes":
        reasons.append(f"PFS status: {pfs}")

    cipher_upper = cipher.upper()
    for marker in WEAK_CIPHER_MARKERS:
        if marker in cipher_upper:
            reasons.append(f"Weak cipher marker: {marker}")
            break

    key_bits = record.get("Key Size (Bits)")
    if isinstance(key_bits, int) and key_bits and key_bits < 2048:
        reasons.append(f"Small key size: {key_bits}")

    return {
        **record,
        "Shadow Crypto Reasons": reasons,
        "Shadow Crypto Severity": (
            "high" if tls_version in {"TLSv1.0", "TLSv1.1"} or any(m in cipher_upper for m in {"NULL", "RC4", "DES", "3DES"})
            else "medium"
        ),
    }



# ═══════════════════════════════════════════════════════════════
# PQC Enrichment Engine
# (ported from pqc_enrichment.py — runs inline after each scan)
# ═══════════════════════════════════════════════════════════════

import datetime as _dt

# ── Field aliases ────────────────────────────────────────────────
_PQC_FIELD: dict[str, tuple] = {
    "tls_version":        ("TLS Version", "Maximum Supported TLS", "TLS_Version",
                           "tls_version", "Max TLS Version", "maxTLSVersion"),
    "min_tls":            ("Minimum Supported TLS", "Min TLS Version",
                           "minTLSVersion", "minimum_supported_tls"),
    "cipher_suite":       ("Cipher Suite", "cipher_suite", "CipherSuite", "cipherSuite"),
    "kex_algo":           ("Key Exchange Algorithm", "Key_Exchange_Algorithm",
                           "KeyExchangeAlgorithm", "kex_algorithm", "keyExchange",
                           "key_exchange_algorithm"),
    "enc_algo":           ("Encryption Algorithm", "Encryption_Algorithm",
                           "EncryptionAlgorithm", "encryption_algorithm"),
    "pfs_status":         ("PFS Status", "PFS_Status", "pfs_status",
                           "Perfect Forward Secrecy", "pfs"),
    "nist_label":         ("NIST PQC Readiness Label", "NIST_PQC_Readiness_Label",
                           "nist_pqc_label", "PQC Label", "pqcLabel"),
    "key_size":           ("Key Size (Bits)", "Key_Size_Bits", "key_size_bits",
                           "KeySize", "key_size", "keySize"),
    "sig_algo":           ("Signature Algorithm", "Signature_Algorithm",
                           "signature_algorithm", "SignatureAlgorithm"),
    "issuer_ca":          ("Issuer CA", "Issuer_CA", "issuer_ca", "IssuerCA",
                           "issuer", "Issuer"),
    "scan_status":        ("Scan Status", "Scan_Status", "scan_status",
                           "ScanStatus", "status"),
    "error_msg":          ("Error", "error", "ErrorMessage", "error_message"),
    "tls_probe":          ("TLS Probe Details", "TLS_Probe_Details",
                           "tls_probe_details", "tls_probes", "tlsProbeDetails"),
    "asset_name":         ("Asset", "asset", "hostname", "host", "domain",
                           "Hostname", "Domain"),
    "tls_supported":      ("TLS Supported", "tls_supported", "tlsSupported"),
    "supported_versions": ("Supported TLS Versions", "supported_tls_versions",
                           "SupportedTLSVersions"),
}

def _pqc_get(obj: dict, field_key: str, default=None):
    for alias in _PQC_FIELD.get(field_key, ()):
        if alias in obj:
            return obj[alias]
    return default

def _pqc_str(obj: dict, field_key: str) -> str:
    v = _pqc_get(obj, field_key, "")
    return str(v).strip() if v is not None else ""


# ── Error classification ─────────────────────────────────────────
_PQC_ERROR_PATTERNS = [
    ("TLS_NEGOTIATION_FAILURE", [
        "no tls version successfully negotiated", "sslv3_alert_handshake_failure",
        "ssl/tls alert handshake failure", "handshake failure", "no protocols available",
        "no shared cipher", "ssl: unsupported protocol", "eof occurred in violation of protocol",
        "wrong version number", "unknown protocol", "sslv3 alert unexpected message",
        "record layer failure", "bad handshake message",
    ]),
    ("HOST_UNREACHABLE", [
        "connection refused", "no route to host", "network unreachable",
        "name or service not known", "nodename nor servname", "getaddrinfo failed",
        "nxdomain", "name resolution failed", "errno 111", "errno 113", "errno 101",
        "[errno 111]", "[errno 113]", "[errno 101]", "connection reset by peer",
        "host not found", "temporary failure in name resolution",
    ]),
    ("CERTIFICATE_ISSUE", [
        "certificate has expired", "certificate verify failed", "certificate_expired",
        "certificate_unknown", "self.signed certificate", "self signed certificate",
        "cert mismatch", "hostname mismatch", "unable to get local issuer certificate",
        "certificate chain error",
    ]),
    ("TIMEOUT", [
        "timed out", "timeout", "connection timed", "read timeout", "etimedout", "[errno 110]",
    ]),
]

_PQC_ERROR_SCORE_DEFAULTS = {
    "TLS_NEGOTIATION_FAILURE": {"tls_score": 1.0, "kex_score": 1.0, "cipher_score": 1.0,
                                "pfs_present": False, "pfs_penalty": 15, "pqc_penalty": 20},
    "HOST_UNREACHABLE": None,
    "CERTIFICATE_ISSUE": {"tls_score": 0.5, "kex_score": 1.0, "cipher_score": 0.5,
                          "pfs_present": True, "pfs_penalty": 0, "pqc_penalty": 20},
    "TIMEOUT": {"tls_score": 1.0, "kex_score": 1.0, "cipher_score": 0.75,
                "pfs_present": False, "pfs_penalty": 15, "pqc_penalty": 20},
    "UNKNOWN_ERROR": {"tls_score": 1.0, "kex_score": 1.0, "cipher_score": 0.75,
                      "pfs_present": False, "pfs_penalty": 15, "pqc_penalty": 20},
}

def _pqc_classify_error(error_msg: str) -> str:
    if not error_msg:
        return "UNKNOWN_ERROR"
    low = error_msg.lower()
    for class_name, patterns in _PQC_ERROR_PATTERNS:
        if any(p in low for p in patterns):
            return class_name
    return "UNKNOWN_ERROR"


# ── TLS version parsing ──────────────────────────────────────────
def _pqc_parse_tls(raw: str) -> float:
    if not raw:
        return -1.0
    up = raw.upper()
    if "SSL" in up:
        m = re.search(r"(\d+(?:\.\d+)?)", up)
        return float(m.group(1)) * 0.1 if m else 0.0
    m = re.search(r"(\d+\.\d+)", up)
    if m:
        return float(m.group(1))
    m = re.search(r"(\d+)", up)
    if m:
        return float(m.group(1))
    return -1.0

def _pqc_supported_probe_versions(probes) -> list:
    if not isinstance(probes, list):
        return []
    result = []
    for p in probes:
        if not isinstance(p, dict):
            continue
        if str(p.get("supported", False)).lower() in ("true", "1", "yes"):
            v = _pqc_parse_tls(str(p.get("tls_version") or ""))
            if v > 0:
                result.append((v, p))
    return sorted(result, key=lambda x: x[0])

def _pqc_effective_tls(asset: dict) -> float:
    for fk in ("tls_version", "min_tls"):
        ver = _pqc_parse_tls(_pqc_str(asset, fk))
        if ver > 0:
            return ver
    sv = _pqc_get(asset, "supported_versions")
    if isinstance(sv, list):
        versions = [_pqc_parse_tls(str(x)) for x in sv if _pqc_parse_tls(str(x)) > 0]
        if versions:
            return max(versions)
    supported = _pqc_supported_probe_versions(_pqc_get(asset, "tls_probe"))
    if supported:
        return supported[-1][0]
    return -1.0

def _pqc_worst_tls(asset: dict, shadow_findings: list = None) -> float:
    shadow_worst = None
    if shadow_findings:
        for finding in shadow_findings:
            if finding.get("finding_type") == "weak_tls":
                weak = finding.get("details", {}).get("weak_versions", [])
                parsed = [_pqc_parse_tls(v) for v in weak if _pqc_parse_tls(v) > 0]
                if parsed:
                    shadow_worst = min(parsed)
                    break
    cbom_worst = None
    min_ver = _pqc_parse_tls(_pqc_str(asset, "min_tls"))
    if min_ver > 0:
        cbom_worst = min_ver
    else:
        sv = _pqc_get(asset, "supported_versions")
        if isinstance(sv, list):
            versions = [_pqc_parse_tls(str(x)) for x in sv if _pqc_parse_tls(str(x)) > 0]
            if versions:
                cbom_worst = min(versions)
        if cbom_worst is None:
            supported = _pqc_supported_probe_versions(_pqc_get(asset, "tls_probe"))
            if supported:
                cbom_worst = supported[0][0]
    candidates = [v for v in (shadow_worst, cbom_worst) if v is not None]
    if candidates:
        return min(candidates)
    return _pqc_effective_tls(asset)

def _pqc_extract_from_best_probe(asset: dict) -> dict:
    supported = _pqc_supported_probe_versions(_pqc_get(asset, "tls_probe"))
    if not supported:
        return {}
    _, best_probe = supported[-1]
    recovered = {}
    for src_key, dst_key in [
        ("cipher_suite",             "Cipher Suite"),
        ("key_exchange_algorithm",   "Key Exchange Algorithm"),
        ("encryption_algorithm",     "Encryption Algorithm"),
        ("pfs_status",               "PFS Status"),
        ("authentication_algorithm", "Authentication Algorithm"),
    ]:
        val = best_probe.get(src_key)
        if val and str(val).strip().lower() not in ("", "null", "none", "unknown"):
            recovered[dst_key] = val
    return recovered

def _pqc_has_any_tls_data(asset: dict) -> bool:
    return (
        _pqc_effective_tls(asset) > 0
        or bool(_pqc_str(asset, "cipher_suite"))
        or bool(_pqc_str(asset, "kex_algo"))
        or bool(_pqc_supported_probe_versions(_pqc_get(asset, "tls_probe")))
    )


# ── PQC / hybrid detection ───────────────────────────────────────
_PQC_KEM_SIGNALS = {
    "KYBER", "ML-KEM", "MLKEM", "CRYSTALS", "FRODO", "NTRU",
    "SABER", "HQC", "BIKE", "MCELIECE", "CLASSIC-MCELIECE", "XWING",
}
_PQC_HYBRID_SIGNALS = {
    "HYBRID", "X25519KYBER", "P256KYBER", "P384KYBER",
    "X25519MLKEM", "P256MLKEM", "P384MLKEM",
}

def _pqc_detect_pqc(asset: dict) -> tuple:
    combined = " ".join(filter(None, [
        _pqc_str(asset, "kex_algo"), _pqc_str(asset, "nist_label"),
        _pqc_str(asset, "cipher_suite"), _pqc_str(asset, "enc_algo"),
    ])).upper()
    uses_pqc    = any(k in combined for k in _PQC_KEM_SIGNALS)
    uses_hybrid = any(k in combined for k in _PQC_HYBRID_SIGNALS)
    return uses_pqc, uses_hybrid


# ── HEI scoring ──────────────────────────────────────────────────
def _pqc_compute_hei(asset: dict, shadow_findings: list = None, error_defaults: dict = None) -> tuple:
    tls_for_risk = _pqc_worst_tls(asset, shadow_findings)
    tls_for_qrmm = _pqc_effective_tls(asset)
    ed = error_defaults or {}

    if ed.get("tls_score") is not None and tls_for_risk < 0:
        tls_score = ed["tls_score"]
    elif tls_for_risk < 0:
        tls_score = 1.0
    elif tls_for_risk <= 1.1:
        tls_score = 1.0
    elif tls_for_risk < 1.3:
        tls_score = 0.5
    else:
        tls_score = 0.0

    uses_pqc, uses_hybrid = _pqc_detect_pqc(asset)
    if uses_pqc:
        kex_score = 0.0
    elif uses_hybrid:
        kex_score = 0.5
    else:
        kex_score = ed.get("kex_score", 1.0)

    combined_c = (_pqc_str(asset, "enc_algo") + " " + _pqc_str(asset, "cipher_suite")).upper()
    if "256" in combined_c or "CHACHA20" in combined_c:
        cipher_score = 0.5
    elif "128" in combined_c or "3DES" in combined_c or "RC4" in combined_c:
        cipher_score = 1.0
    elif combined_c.strip():
        cipher_score = 0.75
    else:
        cipher_score = ed.get("cipher_score", 0.75)

    pfs_raw     = _pqc_str(asset, "pfs_status").upper()
    pfs_present = pfs_raw in ("YES", "TRUE", "ENABLED", "1", "PRESENT")
    kex_raw     = _pqc_str(asset, "kex_algo").upper()
    if "ECDHE" in kex_raw or "DHE" in kex_raw:
        pfs_present = True
    if not pfs_present and not pfs_raw and not kex_raw:
        pfs_present = ed.get("pfs_present", False)
    pfs_penalty = 0 if pfs_present else ed.get("pfs_penalty", 15)

    pqc_any     = uses_pqc or uses_hybrid or bool(_pqc_str(asset, "nist_label"))
    pqc_penalty = 0 if pqc_any else ed.get("pqc_penalty", 20)

    shadow_hei_bonus = 0
    shadow_flags     = []
    if shadow_findings:
        for f in shadow_findings:
            ft = f.get("finding_type", "")
            if ft == "self_signed_cert" and "self_signed" not in shadow_flags:
                shadow_hei_bonus += 10
                shadow_flags.append("self_signed")
            elif ft == "cert_mismatch" and "cert_mismatch" not in shadow_flags:
                shadow_hei_bonus += 5
                shadow_flags.append("cert_mismatch")

    cert_expiry_penalty = 0
    validity        = asset.get("Certificate Validity (Not Before/After)") or {}
    not_after_str   = str(validity.get("Not After") or validity.get("not_after") or "")
    if not_after_str:
        try:
            clean     = re.sub(r"[+-]\d{2}:\d{2}$", "", not_after_str.replace("Z", ""))
            not_after = _dt.datetime.fromisoformat(clean)
            days_left = (not_after - _dt.datetime.now()).days
            if days_left < 0:
                cert_expiry_penalty = 10
            elif days_left < 30:
                cert_expiry_penalty = 7
            elif days_left < 90:
                cert_expiry_penalty = 3
        except (ValueError, TypeError):
            pass

    oid_penalty = 0
    oid         = str(asset.get("OID Reference") or "")
    _WEAK_OIDS  = {"1.2.840.113549.1.1.5", "1.2.840.113549.1.1.4", "1.2.840.10040.4.3"}
    if any(w in oid for w in _WEAK_OIDS):
        oid_penalty = 5

    hei = min(round(
        20 * tls_score + 25 * kex_score + 20 * cipher_score +
        pfs_penalty + pqc_penalty +
        shadow_hei_bonus + cert_expiry_penalty + oid_penalty,
        2), 100.0)

    return hei, {
        "tls_version_for_risk": tls_for_risk,
        "tls_version_for_qrmm": tls_for_qrmm,
        "tls_score":            tls_score,
        "kex_score":            kex_score,
        "uses_pqc_kem":         uses_pqc,
        "uses_hybrid":          uses_hybrid,
        "cipher_score":         cipher_score,
        "pfs_present":          pfs_present,
        "pfs_penalty":          pfs_penalty,
        "pqc_any":              pqc_any,
        "pqc_penalty":          pqc_penalty,
        "shadow_hei_bonus":     shadow_hei_bonus,
        "shadow_flags":         shadow_flags,
        "cert_expiry_penalty":  cert_expiry_penalty,
        "oid_penalty":          oid_penalty,
        "used_error_defaults":  bool(ed),
    }


# ── Risk category ────────────────────────────────────────────────
def _pqc_risk_category(hei: float) -> str:
    if hei <= 25: return "Low"
    if hei <= 50: return "Moderate"
    if hei <= 75: return "High"
    return "Critical"


# ── MDS scoring ──────────────────────────────────────────────────
_PQC_LARGE_CA_ORGS = {
    "DIGICERT", "LETS ENCRYPT", "AMAZON", "MICROSOFT", "GOOGLE",
    "CLOUDFLARE", "COMODO", "SECTIGO", "ENTRUST", "GLOBALSIGN",
    "QUOVADIS", "GODADDY", "IDENTRUST", "VERISIGN", "THAWTE",
    "GEOTRUST", "ACTALIS", "BUYPASS", "TRUSTWAVE",
}

def _pqc_compute_mds(asset: dict, tls_ver: float,
                     shadow_findings: list = None,
                     error_class: str = None) -> tuple:
    if tls_ver < 0:
        legacy = 100 if error_class == "TLS_NEGOTIATION_FAILURE" else 75
    elif tls_ver <= 1.1: legacy = 90
    elif tls_ver < 1.3:  legacy = 50
    else:                legacy = 10

    key_size = 0
    raw_ks   = _pqc_get(asset, "key_size")
    try:
        key_size = int(str(raw_ks).replace(",", "").strip()) if raw_ks else 0
    except (ValueError, TypeError):
        key_size = 0
    nist = _pqc_str(asset, "nist_label")
    if nist:               hardware = 25
    elif key_size >= 4096: hardware = 40
    elif key_size >= 2048: hardware = 55
    elif key_size > 0:     hardware = 75
    else:                  hardware = 65

    sig    = _pqc_str(asset, "sig_algo").upper()
    issuer = _pqc_str(asset, "issuer_ca")
    cert   = 50
    if "SHA1" in sig or "MD5" in sig:
        cert += 20
    elif "SHA384" in sig or "SHA512" in sig or "ECDSA" in sig:
        cert -= 10
    if issuer.upper().count("CN=") + issuer.upper().count("O=") > 4:
        cert += 15
    if shadow_findings:
        for f in shadow_findings:
            if f.get("finding_type") == "self_signed_cert":
                cert += 25
                break
    if shadow_findings:
        for f in shadow_findings:
            if f.get("finding_type") == "cert_mismatch":
                cert += 15
                break
    if error_class == "CERTIFICATE_ISSUE":
        cert = min(cert + 20, 100)
    cert = max(0, min(100, cert))

    issuer_up = issuer.upper()
    asset_up  = _pqc_str(asset, "asset_name").upper()
    vendor = 30 if any(org in issuer_up or org in asset_up for org in _PQC_LARGE_CA_ORGS) else 65

    mds = min(round(0.30 * legacy + 0.20 * hardware + 0.30 * cert + 0.20 * vendor, 2), 100.0)
    return mds, {"legacy_tls_score": legacy, "hardware_score": hardware,
                 "cert_score": cert, "vendor_score": vendor}


# ── QRMM Level ───────────────────────────────────────────────────
def _pqc_compute_qrmm(tls_ver: float, pfs_present: bool,
                      uses_pqc: bool, uses_hybrid: bool) -> dict:
    if uses_pqc and tls_ver >= 1.2:
        return {"level": 3, "label": "Fully PQC Implemented",
                "description": "NIST-approved PQC KEM in use (Kyber/ML-KEM). Legacy algorithms effectively disabled."}
    if uses_hybrid and tls_ver >= 1.2:
        return {"level": 2, "label": "Hybrid Deployment",
                "description": "Classical + PQC key exchange in parallel. Quantum defence-in-depth with backward compatibility."}
    if pfs_present and tls_ver >= 1.2:
        return {"level": 1, "label": "Strong Classical + PFS",
                "description": "Best-practice classical crypto with PFS. No PQC yet; vulnerable to harvest-now attacks."}
    return {"level": 0, "label": "Classical Insecure",
            "description": "Classical crypto with known weaknesses (TLS <= 1.1 or no PFS). Highest quantum exposure."}


# ── Certification status ─────────────────────────────────────────
def _pqc_cert_status(hei: float, uses_pqc: bool, uses_hybrid: bool) -> str:
    if uses_pqc:
        return "PQC Ready"
    if uses_hybrid and hei <= 50:
        return "Hybrid Secure"
    return "Not Quantum Safe"


# ── Asset-key helper ─────────────────────────────────────────────
def _pqc_asset_key(asset: dict) -> str:
    return str(_pqc_get(asset, "asset_name") or "").strip().lower()


# ── Core: enrich one asset ───────────────────────────────────────
def _pqc_enrich_one(asset: dict,
                    shadow_findings: list = None,
                    shadow_record: dict = None) -> dict:
    out = dict(asset)
    if shadow_findings:
        out["Shadow_Crypto_Findings"] = shadow_findings

    scan_status   = _pqc_str(asset, "scan_status").lower()
    error_msg     = _pqc_str(asset, "error_msg")
    is_scan_error = (scan_status == "error") or (
        scan_status not in ("ok", "success", "")
        and scan_status != ""
    ) or (
        scan_status == "" and bool(error_msg)
        and not _pqc_has_any_tls_data(asset)
    )

    error_class = None
    if is_scan_error or error_msg:
        error_class = _pqc_classify_error(error_msg)

    working     = dict(asset)
    data_source = "cbom"

    # Level 1: fill missing cipher/KEX from probe details
    if not _pqc_str(working, "cipher_suite") or not _pqc_str(working, "kex_algo"):
        recovered = _pqc_extract_from_best_probe(working)
        if recovered:
            for k, v in recovered.items():
                if k not in working or not working[k]:
                    working[k] = v
            if not _pqc_str(asset, "cipher_suite") and not _pqc_str(asset, "kex_algo"):
                data_source = "cbom+probe"

    # Level 2: shadow record rescue for error assets
    if is_scan_error and not _pqc_has_any_tls_data(working) and shadow_record:
        shadow_ok = str(_pqc_get(shadow_record, "scan_status") or "").lower()
        if shadow_ok == "ok" or _pqc_effective_tls(shadow_record) > 0:
            working = dict(shadow_record)
            for keep in ("Asset ID", "Asset", "IP Address", "Port"):
                if keep in asset:
                    working[keep] = asset[keep]
            data_source   = "shadow_rescue"
            is_scan_error = False
            error_class   = None

    has_data       = _pqc_has_any_tls_data(working)
    error_defaults = None
    inferred       = False

    if is_scan_error and not has_data and error_class:
        score_defaults = _PQC_ERROR_SCORE_DEFAULTS.get(error_class)
        if score_defaults is None:
            out.update({
                "HEI_Score":            None,
                "Risk_Category":        "Unscored_Unreachable",
                "MDS_Score":            None,
                "QRMM_Level":           {"level": None, "label": "Unreachable",
                                         "description": "Host is not reachable from scanner. Infrastructure issue, not a cryptographic risk."},
                "Certification_Status": "Unscored_Unreachable",
                "Scoring_Confidence":   "none",
                "Error_Classification": error_class,
                "_PQC_Model_Details":   {},
            })
            return out
        error_defaults = score_defaults
        inferred       = True
        data_source    = f"inferred_{error_class.lower()}"

    elif is_scan_error and not has_data:
        error_defaults = _PQC_ERROR_SCORE_DEFAULTS["UNKNOWN_ERROR"]
        inferred       = True
        data_source    = "inferred_unknown_error"

    if not has_data and not inferred:
        out.update({
            "HEI_Score":            None,
            "Risk_Category":        "N/A",
            "MDS_Score":            None,
            "QRMM_Level":           {"level": None, "label": "No Data",
                                     "description": error_msg or "No TLS data available."},
            "Certification_Status": "N/A",
            "Scoring_Confidence":   "none",
            "Error_Classification": error_class,
            "_PQC_Model_Details":   {},
        })
        return out

    hei, hei_bd  = _pqc_compute_hei(working, shadow_findings, error_defaults)
    tls_for_qrmm = hei_bd["tls_version_for_qrmm"]
    uses_pqc     = hei_bd["uses_pqc_kem"]
    uses_hybrid  = hei_bd["uses_hybrid"]
    pfs_present  = hei_bd["pfs_present"]

    mds, mds_fac = _pqc_compute_mds(working, tls_for_qrmm, shadow_findings, error_class)
    qrmm         = _pqc_compute_qrmm(tls_for_qrmm, pfs_present, uses_pqc, uses_hybrid)
    cert_status  = _pqc_cert_status(hei, uses_pqc, uses_hybrid)

    priority_score = round(hei * (1 - mds / 100), 1) if hei is not None else None

    confidence_map = {
        "cbom":                              "full",
        "cbom+probe":                        "partial_probe",
        "shadow_rescue":                     "partial_shadow",
        "inferred_tls_negotiation_failure":  "inferred_tls_failure",
        "inferred_certificate_issue":        "inferred_cert_issue",
        "inferred_timeout":                  "inferred_timeout",
        "inferred_unknown_error":            "inferred_unknown",
    }
    confidence = confidence_map.get(data_source, data_source)

    update = {
        "HEI_Score":            hei,
        "Risk_Category":        _pqc_risk_category(hei),
        "MDS_Score":            mds,
        "QRMM_Level":           qrmm,
        "Certification_Status": cert_status,
        "Remediation_Priority": priority_score,
        "Scoring_Confidence":   confidence,
        "_PQC_Model_Details":   {
            "data_source":   data_source,
            "HEI_breakdown": hei_bd,
            "MDS_factors":   mds_fac,
        },
    }
    if error_class:
        update["Error_Classification"] = error_class
    out.update(update)
    return out


# ── Summary dict ─────────────────────────────────────────────────
def _pqc_summary_dict(enriched: list) -> dict:
    scored  = [a for a in enriched if a.get("HEI_Score") is not None]
    heis    = [a["HEI_Score"] for a in scored]
    mdss    = [a["MDS_Score"]  for a in scored]

    def dist(key, labels):
        return {lb: sum(1 for a in enriched if a.get(key) == lb) for lb in labels}

    def hei_stats(subset):
        h = [a["HEI_Score"] for a in subset if a.get("HEI_Score") is not None]
        return {"count": len(h),
                "avg":   round(sum(h)/len(h), 2) if h else None,
                "min":   min(h) if h else None,
                "max":   max(h) if h else None}

    confidence_counts: dict = {}
    for a in enriched:
        c = a.get("Scoring_Confidence", "none")
        confidence_counts[c] = confidence_counts.get(c, 0) + 1

    full_scored     = [a for a in scored if a.get("Scoring_Confidence") in
                       ("full", "partial_probe", "partial_shadow")]
    inferred_scored = [a for a in scored if a.get("Scoring_Confidence", "").startswith("inferred")]

    now = _dt.datetime.now()
    expiry_counts = {"expired": 0, "within_30d": 0, "within_90d": 0,
                     "within_365d": 0, "ok": 0, "unknown": 0}
    for a in enriched:
        validity      = a.get("Certificate Validity (Not Before/After)") or {}
        not_after_str = str(validity.get("Not After") or validity.get("not_after") or "")
        if not not_after_str:
            expiry_counts["unknown"] += 1
            continue
        try:
            clean     = re.sub(r"[+-]\d{2}:\d{2}$", "", not_after_str.replace("Z", ""))
            not_after = _dt.datetime.fromisoformat(clean)
            days      = (not_after - now).days
            if   days < 0:    expiry_counts["expired"]     += 1
            elif days < 30:   expiry_counts["within_30d"]  += 1
            elif days < 90:   expiry_counts["within_90d"]  += 1
            elif days < 365:  expiry_counts["within_365d"] += 1
            else:             expiry_counts["ok"]          += 1
        except (ValueError, TypeError):
            expiry_counts["unknown"] += 1

    seen_hosts = {}
    for a in full_scored:
        if a.get("Remediation_Priority") is None:
            continue
        hostname = str(a.get("Asset") or a.get("asset") or "").strip().lower()
        existing = seen_hosts.get(hostname)
        if existing is None or (a.get("HEI_Score") or 0) >= (existing.get("HEI_Score") or 0):
            seen_hosts[hostname] = a

    top_priority = sorted(seen_hosts.values(),
                          key=lambda a: a.get("Remediation_Priority", 0),
                          reverse=True)[:10]

    top_priority_list = [
        {"asset":       str(a.get("Asset") or a.get("asset") or "?"),
         "port":        a.get("Port") or a.get("port") or 443,
         "HEI":         a.get("HEI_Score"),
         "MDS":         a.get("MDS_Score"),
         "priority":    a.get("Remediation_Priority"),
         "QRMM":        a.get("QRMM_Level", {}).get("level"),
         "QRMM_label":  a.get("QRMM_Level", {}).get("label", ""),
         "confidence":  a.get("Scoring_Confidence")}
        for a in top_priority
    ]

    unreachable    = sum(1 for a in enriched if a.get("Risk_Category") == "Unscored_Unreachable")
    truly_unscored = sum(1 for a in enriched
                         if a.get("HEI_Score") is None
                         and a.get("Risk_Category") not in ("Unscored_Unreachable",))
    shadow_adjusted = sum(1 for a in enriched
                          if a.get("_PQC_Model_Details", {})
                             .get("HEI_breakdown", {})
                             .get("shadow_hei_bonus", 0) > 0)

    return {
        "total_assets":         len(enriched),
        "scored":               len(scored),
        "scored_full_data":     len(full_scored),
        "scored_inferred":      len(inferred_scored),
        "unscored_unreachable": unreachable,
        "unscored_no_data":     truly_unscored,
        "shadow_annotated":     sum(1 for a in enriched if a.get("Shadow_Crypto_Findings")),
        "shadow_hei_adjusted":  shadow_adjusted,
        "scoring_confidence":   confidence_counts,
        "HEI": hei_stats(scored),
        "HEI_all_scored":       hei_stats(scored),
        "HEI_full_data_only":   hei_stats(full_scored),
        "HEI_inferred_only":    hei_stats(inferred_scored),
        "MDS": {"avg": round(sum(mdss)/len(mdss), 2) if mdss else None,
                "min": min(mdss) if mdss else None,
                "max": max(mdss) if mdss else None},
        "cert_expiry":          expiry_counts,
        "top10_by_priority":    top_priority_list,
        "risk_distribution":    dist("Risk_Category",        ["Low", "Moderate", "High", "Critical"]),
        "cert_distribution":    dist("Certification_Status", ["PQC Ready", "Hybrid Secure", "Not Quantum Safe"]),
        "qrmm_distribution": {
            f"Level_{lvl}": sum(1 for a in scored
                                if isinstance(a.get("QRMM_Level"), dict)
                                and a["QRMM_Level"].get("level") == lvl)
            for lvl in range(4)
        },
    }


def enrich_all(cbom_records: list[dict],
               shadow_records: list[dict]) -> tuple[list[dict], dict]:
    """
    Enrich a list of CBOM records with PQC risk scores.
    Shadow records are used for data rescue and annotation.
    Returns (enriched_list, summary_dict).
    """
    # Build shadow lookup structures from shadow_records
    findings_by_asset: dict[str, list] = {}
    records_by_asset:  dict[str, dict] = {}
    for r in shadow_records:
        key = str(r.get("Asset") or "").strip().lower()
        if key:
            findings_by_asset.setdefault(key, [])
            # Treat each shadow record as a "self_signed_cert" or "weak_tls" finding
            # based on Shadow Crypto Reasons presence
            for reason in (r.get("Shadow Crypto Reasons") or []):
                findings_by_asset[key].append({
                    "finding_type": _shadow_reason_to_type(reason),
                    "asset": key,
                    "details": {"reason": reason},
                })
            records_by_asset[key] = r

    enriched = []
    for a in cbom_records:
        key = _pqc_asset_key(a)
        enriched.append(_pqc_enrich_one(
            a,
            shadow_findings=findings_by_asset.get(key),
            shadow_record=records_by_asset.get(key),
        ))

    summary = _pqc_summary_dict(enriched)
    return enriched, summary


def _shadow_reason_to_type(reason: str) -> str:
    """Map a Shadow Crypto reason string to a finding_type used by the enrichment engine."""
    r = reason.lower()
    if "self" in r and "sign" in r:
        return "self_signed_cert"
    if "mismatch" in r:
        return "cert_mismatch"
    if "tls" in r and ("weak" in r or "1.0" in r or "1.1" in r):
        return "weak_tls"
    return "shadow_crypto"


# -----------------------------
# Merge / diff helpers
# -----------------------------

CBOM_DIFF_KEYS = [
    "TLS Version", "Cipher Suite", "Key Exchange Algorithm",
    "Key Size (Bits)", "PFS Status", "Issuer CA", "Scan Status",
    "IP Address", "NIST PQC Readiness Label",
]


def _read_existing_json(path: Path) -> Any:
    """Read existing JSON file, returning None on any error."""
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _extract_records(data: Any) -> list[dict]:
    """Extract record list from either a flat list or a {records:[...]} / {subdomains:[...]} wrapper."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("records", "subdomains", "findings"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def _extract_subdomains_list(data: Any) -> list[str]:
    """Extract flat list of FQDN strings from the subdomains JSON (flat or wrapped)."""
    if data is None:
        return []
    if isinstance(data, list):
        result = []
        for item in data:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict) and item.get("fqdn"):
                result.append(item["fqdn"])
        return result
    if isinstance(data, dict):
        subs = data.get("subdomains", [])
        result = []
        for item in subs:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict) and item.get("fqdn"):
                result.append(item["fqdn"])
        return result
    return []


def _cbom_fingerprint(record: dict) -> str:
    """Stable hash of key CBOM fields to detect changes."""
    return "|".join(str(record.get(k, "")) for k in CBOM_DIFF_KEYS)


def merge_cbom(existing_records: list[dict], new_records: list[dict]) -> tuple[list[dict], dict]:
    """
    Merge new scan records into existing ones.
    - Key is (Asset, Port) so the same hostname on different ports are tracked independently.
    - New records always win for asset+port combos they contain (updated or unchanged).
    - Existing-only asset+port combos are preserved as-is.
    Returns (merged_list, diff_stats).
    """
    def _cbom_key(r: dict) -> tuple:
        return (str(r.get("Asset", "")), int(r.get("Port", 443)))

    existing_map: dict[tuple, dict] = {_cbom_key(r): r for r in existing_records if r.get("Asset")}
    new_map: dict[tuple, dict] = {_cbom_key(r): r for r in new_records if r.get("Asset")}

    added = 0
    updated = 0
    unchanged = 0

    merged: list[dict] = []

    # Process new records first
    for key, new_rec in new_map.items():
        if key not in existing_map:
            merged.append(new_rec)
            added += 1
        else:
            old_rec = existing_map[key]
            if _cbom_fingerprint(new_rec) != _cbom_fingerprint(old_rec):
                merged.append(new_rec)
                updated += 1
            else:
                merged.append(old_rec)  # keep old (identical)
                unchanged += 1

    # Preserve existing asset+port combos not in new scan
    for key, old_rec in existing_map.items():
        if key not in new_map:
            merged.append(old_rec)

    # Sort by (Asset, Port) for stable output
    merged.sort(key=lambda r: (r.get("Asset", ""), int(r.get("Port", 443))))

    diff = {"added": added, "updated": updated, "unchanged": unchanged, "preserved": len(existing_map) - updated - unchanged}
    return merged, diff


def merge_subdomains(existing_fqdns: list[str], new_fqdns: list[str]) -> tuple[list[str], dict]:
    """Union of old + new subdomains, deduplicated and sorted."""
    existing_set = set(existing_fqdns)
    new_set = set(new_fqdns)
    added = len(new_set - existing_set)
    merged = sorted(existing_set | new_set)
    return merged, {"added": added, "total": len(merged)}


def prepare_outputs(records: list[dict], subdomains: list[str], output_dir: str) -> dict:
    # Include ALL scanned records (ok + error) so new domains are always persisted
    # to cbom.json, subdomains.json, and enriched_cbom.json regardless of TLS outcome.
    new_cbom_records = records
    shadow_records = [build_shadow_crypto_record(r) for r in records if is_valid_crypto_record(r) and is_shadow_crypto_record(r)]

    out = Path(output_dir)
    if out.exists() and out.is_file():
        out = out.parent

    if output_dir and str(output_dir).strip():
        out.mkdir(parents=True, exist_ok=True)

    subdomains_path = out / "subdomains.json"
    cbom_path       = out / "cbom.json"
    shadow_path     = out / "shadow_crypto.json"

    # ── Read existing files ──────────────────────────────────────────────────
    existing_cbom_data     = _read_existing_json(cbom_path)
    existing_sub_data      = _read_existing_json(subdomains_path)

    existing_cbom_records  = _extract_records(existing_cbom_data)
    existing_fqdns         = _extract_subdomains_list(existing_sub_data)

    # ── Merge CBOM ───────────────────────────────────────────────────────────
    merged_cbom, cbom_diff = merge_cbom(existing_cbom_records, new_cbom_records)

    # ── Merge subdomains ─────────────────────────────────────────────────────
    merged_subs, subs_diff = merge_subdomains(existing_fqdns, subdomains)

    # ── Write files only when there are changes ──────────────────────────────
    cbom_changed = cbom_diff["added"] > 0 or cbom_diff["updated"] > 0
    subs_changed = subs_diff["added"] > 0

    if cbom_changed or not cbom_path.exists():
        write_json_file(cbom_path, merged_cbom)

    if subs_changed or not subdomains_path.exists():
        write_json_file(subdomains_path, merged_subs)

    # Shadow crypto always rewritten (derived from merged CBOM)
    merged_shadow = [build_shadow_crypto_record(r) for r in merged_cbom if is_shadow_crypto_record(r)]
    write_json_file(shadow_path, merged_shadow)

    # ── PQC Enrichment → enriched_cbom.json ──────────────────────────────────
    enriched_path = out / "enriched_cbom.json"
    enriched_cbom_records, enrichment_summary = enrich_all(merged_cbom, merged_shadow)
    enriched_output = {
        "_PQC_Enrichment_Summary": enrichment_summary,
        "generated_at_utc":        datetime.now(timezone.utc).isoformat(),
        "count_records":           len(enriched_cbom_records),
        "records":                 enriched_cbom_records,
    }
    write_json_file(enriched_path, enriched_output)

    return {
        "subdomains_path":      str(subdomains_path),
        "cbom_path":            str(cbom_path),
        "shadow_crypto_path":   str(shadow_path),
        "enriched_cbom_path":   str(enriched_path),
        "subdomains":           merged_subs,
        "cbom":                 new_cbom_records,   # return only this-scan records to the UI
        "shadow_crypto":        shadow_records,
        "enrichment_summary":   enrichment_summary,
        "diff": {
            "cbom":       cbom_diff,
            "subdomains": subs_diff,
        },
    }



# -----------------------------
# Scan runner
# -----------------------------
async def run_scan(req: ScanRequest) -> dict:
    normalized_targets = [normalize_host(t) for t in req.targets if normalize_host(t)]
    enumerated_targets = set(normalized_targets)

    host_ips: dict[str, str | None] = {}

    for host in sorted(enumerated_targets):
        ip = await asyncio.get_event_loop().run_in_executor(
            None, resolve_host, host, req.resolve_timeout
        )
        host_ips[host] = ip

    if req.enumerate_subdomains:
        for host in sorted(normalized_targets):
            subs = await asyncio.get_event_loop().run_in_executor(None, enumerate_from_crtsh, host)
            for sub in subs:
                enumerated_targets.add(normalize_host(sub))

        for host in sorted(enumerated_targets):
            if host not in host_ips:
                ip = await asyncio.get_event_loop().run_in_executor(
                    None, resolve_host, host, req.resolve_timeout
                )
                host_ips[host] = ip

    subdomains = sorted(enumerated_targets)

    all_targets: list[tuple[str, int]] = []
    seen_assets: set[tuple[str, int]] = set()

    for host in subdomains:
        for port in req.ports:
            asset_key = (host, int(port))
            if asset_key not in seen_assets:
                seen_assets.add(asset_key)
                all_targets.append(asset_key)

    scanned_records: list[dict] = []

    for host, port in all_targets:
        ip = host_ips.get(host)

        probe_results: dict[str, tuple[bool, dict]] = {}
        for tls_ver in TLS_PROBE_ORDER:
            success, meta = await asyncio.get_event_loop().run_in_executor(
                None, probe_single_tls_version, host, port, tls_ver, req.tls_timeout
            )
            probe_results[tls_ver] = (success, meta)

        record = await asyncio.get_event_loop().run_in_executor(
            None, build_cbom_record, host, port, ip, probe_results, req.tls_timeout
        )
        scanned_records.append(record)

    outputs = prepare_outputs(scanned_records, subdomains, req.output_dir) if req.write_files else {
        "subdomains_path": None,
        "cbom_path": None,
        "shadow_crypto_path": None,
        "subdomains": subdomains,
        "cbom": [r for r in scanned_records if is_valid_crypto_record(r)],
        "shadow_crypto": [build_shadow_crypto_record(r) for r in scanned_records if is_shadow_crypto_record(r) and is_valid_crypto_record(r)],
    }

    return {
        "total_scanned": len(scanned_records),
        "ok": sum(1 for r in scanned_records if r.get("Scan Status") == "ok"),
        "errors": sum(1 for r in scanned_records if r.get("Scan Status") != "ok"),
        "subdomains": outputs["subdomains"],
        "cbom": outputs["cbom"],
        "shadow_crypto": outputs["shadow_crypto"],
        "subdomains_path": outputs["subdomains_path"],
        "cbom_path": outputs["cbom_path"],
        "shadow_crypto_path": outputs["shadow_crypto_path"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# -----------------------------
# SSE stream
# -----------------------------
async def run_scan_stream(req: ScanRequest):
    def emit(event: str, data: Any) -> str:
        return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"

    def log(level: str, msg: str) -> str:
        return emit("log", {"level": level, "message": msg})

    yield log("INFO", "Starting scan...")
    yield log("INFO", f"Targets: {', '.join(req.targets)}")
    yield log("INFO", f"Ports: {req.ports}")
    yield emit("progress", {"phase": 0, "pct": 5, "label": "Resolving DNS"})

    normalized_targets = [normalize_host(t) for t in req.targets if normalize_host(t)]
    enumerated_targets = set(normalized_targets)
    host_ips: dict[str, str | None] = {}

    for host in sorted(enumerated_targets):
        yield log("INFO", f"Resolving {host}...")
        ip = await asyncio.get_event_loop().run_in_executor(
            None, resolve_host, host, req.resolve_timeout
        )
        host_ips[host] = ip
        if ip:
            yield log("INFO", f"  {host} -> {ip}")
        else:
            yield log("WARN", f"  {host} -> could not resolve (will still attempt probe)")

    yield emit("progress", {"phase": 0, "pct": 15, "label": "Resolving DNS"})

    yield emit("progress", {"phase": 1, "pct": 20, "label": "Enumerating Assets"})

    if req.enumerate_subdomains:
        yield log("INFO", "Enumerating subdomains via crt.sh...")
        for host in sorted(normalized_targets):
            yield log("INFO", f"  Querying crt.sh for {host}...")
            subs = await asyncio.get_event_loop().run_in_executor(None, enumerate_from_crtsh, host)
            if subs:
                yield log("INFO", f"  Found {len(subs)} subdomains for {host}")
                for sub in subs:
                    sub = normalize_host(sub)
                    if sub not in enumerated_targets:
                        enumerated_targets.add(sub)
                        ip = await asyncio.get_event_loop().run_in_executor(
                            None, resolve_host, sub, req.resolve_timeout
                        )
                        host_ips[sub] = ip
            else:
                yield log("INFO", f"  No subdomains found for {host}")

    subdomains = sorted(enumerated_targets)
    all_targets: list[tuple[str, int]] = []
    seen_assets: set[tuple[str, int]] = set()
    for host in subdomains:
        for port in req.ports:
            asset_key = (host, int(port))
            if asset_key not in seen_assets:
                seen_assets.add(asset_key)
                all_targets.append(asset_key)

    yield log("INFO", f"Probing {len(all_targets)} target(s)...")
    yield emit("progress", {"phase": 1, "pct": 35, "label": "Enumerating Assets"})
    yield emit("progress", {"phase": 2, "pct": 40, "label": "TLS Handshake Probes"})

    scanned_records: list[dict] = []
    total = len(all_targets)

    for idx, (host, port) in enumerate(all_targets):
        ip = host_ips.get(host)
        yield log("INFO", f"Probing {host}:{port}...")

        probe_results: dict[str, tuple[bool, dict]] = {}

        for tls_ver in TLS_PROBE_ORDER:
            success, meta = await asyncio.get_event_loop().run_in_executor(
                None, probe_single_tls_version, host, port, tls_ver, req.tls_timeout
            )
            probe_results[tls_ver] = (success, meta)

            if success:
                yield log("DEBUG", f"  {tls_ver} ✓ — cipher: {meta.get('cipher_tuple', ('?',))[0]}")
            else:
                yield log("DEBUG", f"  {tls_ver} ✗")

        supported = [v for v in TLS_PROBE_ORDER if probe_results.get(v, (False,))[0]]

        if supported:
            min_ver = supported[0]
            max_ver = supported[-1]
            if min_ver in ("TLSv1.0", "TLSv1.1"):
                yield log("WARN", f"  {host}: Supports deprecated {min_ver}")
            _, best_meta = probe_results[max_ver]
            ct = best_meta.get("cipher_tuple")
            if ct and ("DES" in ct[0] or "RC4" in ct[0] or "NULL" in ct[0]):
                yield log("WARN", f"  {host}: Weak cipher — {ct[0]}")
            latency = best_meta.get("latency_ms")
            if latency:
                yield log("INFO", f"  {host} — latency: {latency}ms")
        else:
            yield log("ERROR", f"  {host}:{port} — No TLS version successfully negotiated")

        record = await asyncio.get_event_loop().run_in_executor(
            None, build_cbom_record, host, port, ip, probe_results, req.tls_timeout
        )

        scanned_records.append(record)

        include_cbom = is_valid_crypto_record(record)
        include_shadow = is_shadow_crypto_record(record)

        yield emit("result", {
            **record,
            "Included In CBOM": include_cbom,
            "Included In Shadow Crypto": include_shadow,
        })

        pct = 40 + int((idx + 1) / total * 45)
        yield emit("progress", {"phase": 2, "pct": pct, "label": "TLS Handshake Probes"})

    yield emit("progress", {"phase": 3, "pct": 88, "label": "Cert / Web Fingerprint Summary"})
    yield log("INFO", "Fingerprinting complete.")

    outputs = prepare_outputs(scanned_records, subdomains, req.output_dir) if req.write_files else {
        "subdomains_path": None,
        "cbom_path": None,
        "shadow_crypto_path": None,
        "subdomains": subdomains,
        "cbom": [r for r in scanned_records if is_valid_crypto_record(r)],
        "shadow_crypto": [build_shadow_crypto_record(r) for r in scanned_records if is_shadow_crypto_record(r) and is_valid_crypto_record(r)],
        "diff": {"cbom": {"added": 0, "updated": 0, "unchanged": 0, "preserved": 0}, "subdomains": {"added": 0, "total": 0}},
    }

    ok_count = sum(1 for r in outputs["cbom"] if r.get("Scan Status") == "ok")
    err_count = len(scanned_records) - ok_count

    yield emit("progress", {"phase": 4, "pct": 95, "label": "Writing Outputs"})
    diff = outputs.get("diff", {})
    cbom_diff = diff.get("cbom", {})
    subs_diff = diff.get("subdomains", {})
    yield log("INFO", f"Merge complete — CBOM: +{cbom_diff.get('added',0)} new, ~{cbom_diff.get('updated',0)} updated, ={cbom_diff.get('unchanged',0)} unchanged, {cbom_diff.get('preserved',0)} preserved from previous scan")
    yield log("INFO", f"Subdomains: +{subs_diff.get('added',0)} new, {subs_diff.get('total',0)} total")
    yield log("INFO", f"Running PQC enrichment on {len(outputs['cbom'])} records...")
    yield log("INFO", f"Writing cbom.json, shadow_crypto.json, enriched_cbom.json to {req.output_dir}")
    yield emit("progress", {"phase": 4, "pct": 100, "label": "Writing Outputs"})
    yield log("INFO", f"✅ Scan complete. {len(scanned_records)} asset(s) processed.")

    yield emit("done", {
        "total_scanned":      len(scanned_records),
        "ok":                 ok_count,
        "errors":             err_count,
        "subdomains":         outputs["subdomains"],
        "cbom":               outputs["cbom"],
        "shadow_crypto":      outputs["shadow_crypto"],
        "subdomains_path":    outputs["subdomains_path"],
        "cbom_path":          outputs["cbom_path"],
        "shadow_crypto_path": outputs["shadow_crypto_path"],
        "enriched_cbom_path": outputs.get("enriched_cbom_path"),
        "enrichment_summary": outputs.get("enrichment_summary"),
        "diff":               outputs.get("diff", {}),
        "scanned_at":         datetime.now(timezone.utc).isoformat(),
    })


# -----------------------------
# Routes
# -----------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "QRIE Scanner API"}


@app.post("/api/scan/stream")
async def scan_stream(req: ScanRequest):
    return StreamingResponse(
        run_scan_stream(req),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scan")
async def scan_blocking(req: ScanRequest):
    return await run_scan(req)


# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("scanner_api:app", host="0.0.0.0", port=8000, reload=True)
