# VANTABLACK: TECHNICAL FOOTPRINT & FORENSIC REPORT

This document lists the forensics and technical traces left by the VANTABLACK infrastructure during a network audit.

## 1. Network & DNS Traces
- **DNS Patterns**: Use of typosquatted domains (e.g., `login-microsoft.net`).
- **DNS TTL**: Low TTL (often 60s) to allow rapid IP rotation.
- **PTR Records**: Often absent or pointing to generic datacenter hostnames if residential proxies are inactive.

## 2. TLS Fingerprinting (Ja3)
- **Engine Signature**: The Evilginx binary has a specific Ja3 fingerprint based on its Go compilation.
- **Anomalies**: Use of auto-generated Let's Encrypt certificates on deep sub-domains.

## 3. HTTP Header Anomalies
- **X-Forwarded-For**: May contain the real IP of the visitor or the orchestrator.
- **Server Header**: Often reveals `nginx` even if the target uses a proprietary server.
- **Cache-Control**: Forced `no-store` or `no-cache` to prevent caching of interception scripts.

## 4. Nervous System API Signatures
- **FastAPI Headers**: The API server may return headers like `X-Process-Time` if not disabled.
- **Endpoint Predictability**: The existence of predictable endpoints (e.g., `/capture`) is a strong signature.

## 5. Temporal Fingerprints (TTFB)
- **MITM Latency**: An additional delay of 50ms to 300ms (Time To First Byte) is induced by the reverse proxy during dynamic filter processing.
