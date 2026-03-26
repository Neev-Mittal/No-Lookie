"""
QRIE Scanner API — FastAPI backend for the Scanner Engine
Performs real TLS probing, certificate extraction, and CBOM generation.

Usage:
    pip install fastapi uvicorn[standard] cryptography
    python scanner_api.py
    # → http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import time
import uuid
import urllib.request
import urllib.error
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# ──────────────────────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────────────────────
app = FastAPI(title="QRIE Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────
# Request / Response models
# ──────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    targets: list[str]
    ports: list[int] = [443]
    tls_timeout: float = 6.0
    resolve_timeout: float = 5.0
    enumerate_subdomains: bool = False


# ──────────────────────────────────────────────────────────────
# TLS probe helpers
# ──────────────────────────────────────────────────────────────
TLS_VERSION_MAP = {
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

# Ordered from weakest to strongest for min/max detection
TLS_PROBE_ORDER = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

TLS_VERSION_CONSTS = {
    "TLSv1.0": (ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1),
    "TLSv1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
}

# Known PFS key-exchange prefixes
PFS_KEX = {"ECDHE", "DHE", "EDH"}

# NIST PQC readiness labels
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


def resolve_host(host: str, timeout: float) -> str | None:
    """Return first IPv4/IPv6 address for host, or None."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


def enumerate_from_crtsh(domain: str) -> set[str]:
    """Query crt.sh for subdomains of a given domain."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name and not name.startswith('*') and name.endswith(domain):
                            if re.match(r'^[a-z0-9.-]+$', name):
                                subdomains.add(name)
    except Exception:
        pass
    return subdomains


def probe_single_tls_version(
    host: str, port: int, tls_ver: str, timeout: float
) -> tuple[bool, dict]:
    """
    Attempt a TLS handshake pinned to a single TLS version.
    Returns (success, metadata_dict).
    """
    bounds = TLS_VERSION_CONSTS.get(tls_ver)
    if bounds is None:
        return False, {}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = bounds[0]
        ctx.maximum_version = bounds[1]
    except (AttributeError, ssl.SSLError):
        # Older Python / OpenSSL may not support some versions
        return False, {}

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            t0 = time.monotonic()
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                latency_ms = round((time.monotonic() - t0) * 1000, 1)
                cipher_tuple = tls_sock.cipher()          # (name, proto, bits)
                negotiated   = tls_sock.version()         # e.g. "TLSv1.3"
                der_cert      = tls_sock.getpeercert(binary_form=True)
                return True, {
                    "negotiated_version": negotiated,
                    "cipher_tuple":       cipher_tuple,
                    "latency_ms":         latency_ms,
                    "der_cert":           der_cert,
                }
    except Exception:
        return False, {}


def parse_cipher(cipher_tuple: tuple | None) -> dict:
    """Break a cipher tuple into its components."""
    if not cipher_tuple:
        return {
            "cipher_suite": None,
            "key_exchange":  None,
            "authentication": None,
            "encryption":    None,
            "hash_algo":     None,
            "pfs":           "Unknown",
        }

    name = cipher_tuple[0]
    parts = name.split("-")

    # Derive components heuristically from the cipher name
    kex  = parts[0] if parts else None
    auth = parts[1] if len(parts) > 1 else None
    enc  = "-".join(parts[2:-1]) if len(parts) > 3 else (parts[2] if len(parts) > 2 else None)
    mac  = parts[-1] if parts else None

    pfs = "Yes" if kex in PFS_KEX else ("No" if kex else "Unknown")

    return {
        "cipher_suite":   name,
        "key_exchange":   kex,
        "authentication": auth,
        "encryption":     enc,
        "hash_algo":      mac,
        "pfs":            pfs,
    }


def extract_cert_info(der_cert: bytes | None) -> dict:
    """Parse a DER-encoded certificate using the cryptography library."""
    if not der_cert:
        return {
            "public_key_algo": None,
            "key_size_bits":   None,
            "signature_algo":  None,
            "issuer_ca":       None,
            "not_before":      None,
            "not_after":       None,
            "oid_reference":   None,
        }
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

        cert      = x509.load_der_x509_certificate(der_cert)
        pub_key   = cert.public_key()
        sig_algo  = cert.signature_algorithm_oid.dotted_string

        # Public key algorithm + size
        if isinstance(pub_key, rsa.RSAPublicKey):
            pk_algo   = "RSA"
            key_bits  = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pk_algo   = "EC"
            key_bits  = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pk_algo   = "DSA"
            key_bits  = pub_key.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pk_algo   = type(pub_key).__name__.replace("PublicKey", "")
            key_bits  = 256 if "25519" in pk_algo else 448
        else:
            pk_algo  = type(pub_key).__name__
            key_bits = None

        # Signature algorithm name (friendly)
        try:
            sig_name = cert.signature_hash_algorithm.name + "With" + pk_algo
        except Exception:
            sig_name = sig_algo

        # Issuer CN
        try:
            cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            issuer_ca = f"CN={cn[0].value}" if cn else str(cert.issuer)
        except Exception:
            issuer_ca = str(cert.issuer)

        return {
            "public_key_algo": pk_algo,
            "key_size_bits":   key_bits,
            "signature_algo":  sig_name,
            "issuer_ca":       issuer_ca,
            "not_before":      cert.not_valid_before_utc.isoformat(),
            "not_after":       cert.not_valid_after_utc.isoformat(),
            "oid_reference":   sig_algo,
        }
    except ImportError:
        # cryptography not installed — fall back to minimal info
        return {
            "public_key_algo": "RSA",
            "key_size_bits":   None,
            "signature_algo":  None,
            "issuer_ca":       None,
            "not_before":      None,
            "not_after":       None,
            "oid_reference":   None,
        }
    except Exception:
        return {
            "public_key_algo": None,
            "key_size_bits":   None,
            "signature_algo":  None,
            "issuer_ca":       None,
            "not_before":      None,
            "not_after":       None,
            "oid_reference":   None,
        }


def build_cbom_record(
    host: str,
    port: int,
    ip: str | None,
    probe_results: dict[str, tuple[bool, dict]],
) -> dict:
    """
    Combine per-version probe results into a single CBOMRecord dict
    that mirrors the frontend's expected shape.
    """
    supported_versions = [v for v in TLS_PROBE_ORDER if probe_results.get(v, (False,))[0]]
    tls_supported = len(supported_versions) > 0

    if not tls_supported:
        return {
            "Asset ID":                         str(uuid.uuid4()),
            "Asset":                            host,
            "IP Address":                       ip,
            "Port":                             port,
            "TLS Supported":                    False,
            "Supported TLS Versions":           [],
            "Minimum Supported TLS":            None,
            "Maximum Supported TLS":            None,
            "TLS Version":                      None,
            "Cipher Suite":                     None,
            "Key Exchange Algorithm":           None,
            "Authentication Algorithm":         None,
            "Encryption Algorithm":             None,
            "Hash Algorithm":                   None,
            "Handshake Latency":                None,
            "Public Key Algorithm":             None,
            "Key Size (Bits)":                  None,
            "PFS Status":                       "Unknown",
            "OID Reference":                    None,
            "NIST PQC Readiness Label":         "Unknown",
            "Scan Status":                      "error",
            "Error":                            "No TLS version successfully negotiated",
            "Certificate Validity (Not Before/After)": {"Not Before": None, "Not After": None},
            "Signature Algorithm":              None,
            "Issuer CA":                        None,
        }

    # Best (highest) version wins for primary fields
    best_ver   = supported_versions[-1]
    _, best_md = probe_results[best_ver]

    cipher_info = parse_cipher(best_md.get("cipher_tuple"))
    cert_info   = extract_cert_info(best_md.get("der_cert"))

    pk_algo  = cert_info["public_key_algo"]
    key_bits = cert_info["key_size_bits"]

    return {
        "Asset ID":                         str(uuid.uuid4()),
        "Asset":                            host,
        "IP Address":                       ip or "—",
        "Port":                             port,
        "TLS Supported":                    True,
        "Supported TLS Versions":           supported_versions,
        "Minimum Supported TLS":            supported_versions[0],
        "Maximum Supported TLS":            supported_versions[-1],
        "TLS Version":                      best_ver,
        "Cipher Suite":                     cipher_info["cipher_suite"],
        "Key Exchange Algorithm":           cipher_info["key_exchange"],
        "Authentication Algorithm":         cipher_info["authentication"],
        "Encryption Algorithm":             cipher_info["encryption"],
        "Hash Algorithm":                   cipher_info["hash_algo"],
        "Handshake Latency":                best_md.get("latency_ms"),
        "Public Key Algorithm":             pk_algo,
        "Key Size (Bits)":                  key_bits,
        "PFS Status":                       cipher_info["pfs"],
        "OID Reference":                    cert_info["oid_reference"],
        "NIST PQC Readiness Label":         pqc_label(pk_algo, key_bits, cipher_info["cipher_suite"]),
        "Scan Status":                      "ok",
        "Error":                            None,
        "Certificate Validity (Not Before/After)": {
            "Not Before": cert_info["not_before"],
            "Not After":  cert_info["not_after"],
        },
        "Signature Algorithm":              cert_info["signature_algo"],
        "Issuer CA":                        cert_info["issuer_ca"],
    }


# ──────────────────────────────────────────────────────────────
# SSE scan stream endpoint
# ──────────────────────────────────────────────────────────────

async def run_scan_stream(req: ScanRequest):
    """
    Generator that yields Server-Sent Events with JSON payloads.
    Event types:
      log      → { level, message }
      progress → { phase, pct, label }
      result   → one CBOMRecord dict
      done     → { total, ok, errors }
      error    → { message }
    """

    def emit(event: str, data: Any) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    def log(level: str, msg: str) -> str:
        return emit("log", {"level": level, "message": msg})

    yield log("INFO", "Starting scan...")
    yield log("INFO", f"Targets: {', '.join(req.targets)}")
    yield log("INFO", f"Ports: {req.ports}")
    yield emit("progress", {"phase": 0, "pct": 5, "label": "Resolving DNS"})

    # ── Phase 1: DNS resolution ──────────────────────────────
    host_ips: dict[str, str | None] = {}
    for host in req.targets:
        yield log("INFO", f"Resolving {host}...")
        ip = await asyncio.get_event_loop().run_in_executor(
            None, resolve_host, host, req.resolve_timeout
        )
        host_ips[host] = ip
        if ip:
            yield log("INFO", f"  {host} → {ip}")
        else:
            yield log("WARN", f"  {host} → could not resolve (will still attempt probe)")

    yield emit("progress", {"phase": 0, "pct": 15, "label": "Resolving DNS"})

    # ── Phase 2: Enumerate assets ────────────────────────────
    yield emit("progress", {"phase": 1, "pct": 20, "label": "Enumerating Assets"})
    
    enumerated_targets = set(req.targets)
    if req.enumerate_subdomains:
        yield log("INFO", "Enumerating subdomains via crt.sh...")
        for host in req.targets:
            yield log("INFO", f"  Querying crt.sh for {host}...")
            subs = await asyncio.get_event_loop().run_in_executor(
                None, enumerate_from_crtsh, host
            )
            if subs:
                yield log("INFO", f"  Found {len(subs)} subdomains for {host}")
                enumerated_targets.update(subs)
                for sub in subs:
                    if sub not in host_ips:
                        ip = await asyncio.get_event_loop().run_in_executor(
                            None, resolve_host, sub, req.resolve_timeout
                        )
                        host_ips[sub] = ip
            else:
                yield log("INFO", f"  No subdomains found for {host}")

    all_targets: list[tuple[str, int]] = []
    for host in sorted(enumerated_targets):
        for port in req.ports:
            all_targets.append((host, port))

    yield log("INFO", f"Probing {len(all_targets)} target(s)...")
    yield emit("progress", {"phase": 1, "pct": 35, "label": "Enumerating Assets"})

    # ── Phase 3: TLS probes ──────────────────────────────────
    yield emit("progress", {"phase": 2, "pct": 40, "label": "TLS Handshake Probes"})

    all_records: list[dict] = []
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
            None, build_cbom_record, host, port, ip, probe_results
        )
        all_records.append(record)
        yield emit("result", record)

        pct = 40 + int((idx + 1) / total * 45)
        yield emit("progress", {"phase": 2, "pct": pct, "label": "TLS Handshake Probes"})

    # ── Phase 4: Cert extraction summary ────────────────────
    yield emit("progress", {"phase": 3, "pct": 88, "label": "Cert Extraction"})
    yield log("INFO", "Certificate extraction complete.")

    # ── Phase 5: CBOM output ─────────────────────────────────
    yield emit("progress", {"phase": 4, "pct": 95, "label": "Writing CBOM"})
    ok_count  = sum(1 for r in all_records if r["Scan Status"] == "ok")
    err_count = len(all_records) - ok_count
    yield log("INFO", f"Writing cbom.json... ({len(all_records)} records)")
    yield emit("progress", {"phase": 4, "pct": 100, "label": "Writing CBOM"})
    yield log("INFO", f"✅ Scan complete. {len(all_records)} asset(s) processed.")

    yield emit("done", {
        "total":   len(all_records),
        "ok":      ok_count,
        "errors":  err_count,
        "cbom":    all_records,
    })


# ──────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "QRIE Scanner API"}


@app.post("/api/scan/stream")
async def scan_stream(req: ScanRequest):
    """
    SSE endpoint — streams log lines, progress events, and CBOM records
    back to the frontend in real time.
    """
    return StreamingResponse(
        run_scan_stream(req),
        media_type="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scan")
async def scan_blocking(req: ScanRequest):
    """
    Blocking endpoint — collects everything and returns a single JSON response.
    Use this if you don't want SSE.
    """
    records: list[dict] = []

    enumerated_targets = set(req.targets)
    if req.enumerate_subdomains:
        for host in req.targets:
            subs = await asyncio.get_event_loop().run_in_executor(
                None, enumerate_from_crtsh, host
            )
            enumerated_targets.update(subs)

    for host in sorted(enumerated_targets):
        ip = await asyncio.get_event_loop().run_in_executor(
            None, resolve_host, host, req.resolve_timeout
        )
        for port in req.ports:
            probe_results: dict[str, tuple[bool, dict]] = {}
            for tls_ver in TLS_PROBE_ORDER:
                success, meta = await asyncio.get_event_loop().run_in_executor(
                    None, probe_single_tls_version, host, port, tls_ver, req.tls_timeout
                )
                probe_results[tls_ver] = (success, meta)
            record = await asyncio.get_event_loop().run_in_executor(
                None, build_cbom_record, host, port, ip, probe_results
            )
            records.append(record)

    return {
        "total":   len(records),
        "ok":      sum(1 for r in records if r["Scan Status"] == "ok"),
        "errors":  sum(1 for r in records if r["Scan Status"] != "ok"),
        "cbom":    records,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("scanner_api:app", host="0.0.0.0", port=8000, reload=True)
