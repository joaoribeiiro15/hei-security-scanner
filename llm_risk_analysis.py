#!/usr/bin/env python3
"""
llm_risk_analysis.py
====================
LLM-powered risk analysis that reads the three scanner result CSVs
(HTTPS/TLS, Security Headers, DNSSEC) and produces a per-institution
risk assessment report with mitigation recommendations.

The script merges all three datasets by institution ID, builds a structured
security profile for each HEI, and sends it to a language model. Output is
a Markdown report and a summary CSV.

Supported backends
------------------
  lmstudio   LM Studio server on the local machine or network.
             Exposes an OpenAI-compatible API on port 1234 by default.
  ollama     Ollama local daemon.
  openai     OpenAI API (requires --api-key).
  custom     Any OpenAI-compatible endpoint supplied via --api-url.

Quick-start examples
--------------------
  # LM Studio on the same machine (auto-selects first loaded model):
  python llm_risk_analysis.py --backend lmstudio \\
      --https-csv   src/results/https/XX_https_scanner.csv \\
      --headers-csv src/results/headers/sh_final_result_with_scores_unique_hei.csv \\
      --dnssec-csv  src/results/dnssec/XX_dnssec_scanner.csv

  # LM Studio on another machine in the network:
  python llm_risk_analysis.py --backend lmstudio \\
      --lmstudio-host 192.168.1.100 \\
      --https-csv   src/results/https/XX_https_scanner.csv \\
      --headers-csv src/results/headers/sh_final_result_with_scores_unique_hei.csv \\
      --dnssec-csv  src/results/dnssec/XX_dnssec_scanner.csv

  # Specify a model explicitly:
  python llm_risk_analysis.py --backend lmstudio \\
      --lmstudio-host 192.168.1.100 \\
      --model "lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF" \\
      --https-csv ... --headers-csv ... --dnssec-csv ...

  # List models currently available on a LM Studio server:
  python llm_risk_analysis.py --backend lmstudio \\
      --lmstudio-host 192.168.1.100 --list-models

  # Ollama local:
  python llm_risk_analysis.py --backend ollama \\
      --https-csv ... --headers-csv ... --dnssec-csv ...

  # OpenAI:
  python llm_risk_analysis.py --backend openai --api-key sk-... --model gpt-4o \\
      --https-csv ... --headers-csv ... --dnssec-csv ...

  # Custom OpenAI-compatible server:
  python llm_risk_analysis.py --backend custom \\
      --api-url http://myserver:8080/v1/chat/completions --model my-model \\
      --https-csv ... --headers-csv ... --dnssec-csv ...

  # Test with only the first 3 institutions:
  python llm_risk_analysis.py --backend lmstudio --limit 3 \\
      --https-csv ... --headers-csv ... --dnssec-csv ...

Requirements:
    pip install requests pandas
"""

import argparse
import csv
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import pandas as pd
import requests

# Reuse the multi-country ID/column normalisation already fixed for the
# consolidated-score pipeline (src/consolidation/final_score.py) so the
# same institution resolves to the same "ID" here as it does on the
# dashboard, regardless of which country's source schema it came from
# (ETER_ID for DE/FR/IT, Id for PL, ID for NO).
from src.consolidation.final_score import _load_all_scanner_latest, _load_latest, _normalise_df

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend definitions
# ---------------------------------------------------------------------------

BACKENDS = {
    "lmstudio": {
        "description":   "LM Studio local/network server (OpenAI-compatible)",
        "default_url":   "http://localhost:1234/v1/chat/completions",
        "models_url":    "http://localhost:1234/v1/models",
        "format":        "openai",
        "default_model": None,
        "requires_key":  False,
    },
    "ollama": {
        "description":   "Ollama local daemon",
        "default_url":   "http://localhost:11434/api/chat",
        "models_url":    "http://localhost:11434/api/tags",
        "format":        "ollama",
        "default_model": "llama3.1:8b",
        "requires_key":  False,
    },
    "openai": {
        "description":   "OpenAI API",
        "default_url":   "https://api.openai.com/v1/chat/completions",
        "models_url":    "https://api.openai.com/v1/models",
        "format":        "openai",
        "default_model": "gpt-4o",
        "requires_key":  True,
    },
    "custom": {
        "description":   "Any OpenAI-compatible endpoint (supply --api-url and --model)",
        "default_url":   None,
        "models_url":    None,
        "format":        "openai",
        "default_model": None,
        "requires_key":  False,
    },
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

# System prompt: instructs the model to output JSON directly without chain-of-thought.
SYSTEM_PROMPT = """You are a cybersecurity expert. You receive web security scan data for a European higher education institution (HEI) — the institution may be located in any of several countries analysed in this project (e.g. Norway, Germany, France, Italy, Poland) — and return a JSON risk assessment.

Rules:
- Output JSON only. No reasoning, no explanation, no markdown, no code fences.
- Always respond in English regardless of the institution name or domain.
- Only include in "findings" the checks that FAILED (passed=false). Omit checks that passed.
- For each failed check, use EXACTLY the test name from the table below and the exact score_impact listed.
- Compute risk_score: start at 100 and sum the score_impact of every failing check. Clamp to [0, 100].
- Assign risk_level from final score: 85-100=Minimal, 70-84=Low, 50-69=Medium, 30-49=High, 0-29=Critical.
- Do NOT copy example values from the schema. Replace all placeholders with computed values.
- The "reason" field must state WHAT was detected (or not detected) and WHY it is a security risk — be technically precise, name the specific header, directive, or protocol involved.
- The "recommendation" field must give a concrete, actionable fix — name the exact header value, directive, or configuration change required. Follow the per-check guidance at the end of this prompt exactly.

Per-check scoring table — use these EXACT test names and score_impact values:

HTTPS dimension:
  "Valid TLS Certificate"          score_impact=-20  (fail if cert_valid=No)
  "HTTPS Redirect"                 score_impact=-10  (fail if http does not redirect to https)
  "TLS 1.3 Supported"              score_impact=-5   (fail if tls13=No)
  "TLS 1.0 / 1.1 Disabled"        score_impact=-10  (fail if tls10=Yes)
  "SSLv3 Disabled"                 score_impact=-15  (fail if sslv3=Yes)
  "HTTPS Grade A or Better"        score_impact=-15  (fail if grade not in A+/A)
  "HSTS Header Present (HTTPS)"    score_impact=-10  (fail if hsts=No)
  "OCSP Stapling"                  score_impact=-5   (fail if ocsp=No)
  "CAA Records"                    score_impact=-5   (fail if caa=No)
  "Certificate Transparency"       score_impact=-3   (fail if ct=No)
  "HTTP/2 Support"                 score_impact=-2   (fail if http2=No)

HEADERS dimension:
  "Strict-Transport-Security"          score_impact=-20  (fail if hdr_hsts=No/Missing)
  "Content Security Policy (CSP)"      score_impact=-25  (fail if csp=No/Missing/Unsafe)
  "X-Frame-Options"                    score_impact=-10  (fail if xfo=No/Missing)
  "X-Content-Type-Options"             score_impact=-10  (fail if xcto=No/Missing)
  "Referrer Policy"                    score_impact=-5   (fail if rp=No/Missing/Unsafe)
  "Permissions Policy"                 score_impact=-5   (fail if pp=No/Missing)
  "Cross-Origin-Opener-Policy"         score_impact=-5   (fail if COOP header is missing)
  "Cross-Origin-Embedder-Policy"       score_impact=-3   (fail if COEP header is missing)
  "Cross-Origin-Resource-Policy"       score_impact=-3   (fail if CORP header is missing)
  "Access-Control-Allow-Origin (CORS)" score_impact=-8   (fail if CORS allows wildcard or overly permissive origin)
  "Set-Cookie Security"                score_impact=-10  (fail if Set-Cookie lacks Secure, HttpOnly, or SameSite flags)
  "Subresource Integrity (SRI)"        score_impact=-10  (fail if external scripts loaded without SRI)
  "X-XSS-Protection"                   score_impact=-5   (fail if header is missing or not set to 0)

DNSSEC dimension:
  "DNSSEC Signed"                  score_impact=-15  (fail if status=Missing/Unsigned/No)
  "DNSSEC Algorithm Strength"      score_impact=-5   (fail if score<80 or algorithm weak)
  "NSEC3 Used (Not NSEC)"          score_impact=-3   (fail if nsec=NSEC or unknown)

Personalisation requirements — these are MANDATORY:
- Every "reason" field MUST begin by naming the specific institution (use the name from the HEI input line) and its domain. Example: "University X's website at domain.edu does not..."
- Every "reason" field MUST reference the specific scan value that triggered the failure (e.g. the actual grade, the specific protocol enabled, the actual header value or its absence). Do NOT write generic text that could apply to any institution.
- Every "recommendation" field MUST name the institution's domain where a configuration change is required. Example: "Configure domain.edu's web server to..."
- Two institutions with the same failing check MUST receive different reason text that reflects their unique scan data and context. Identical reasons across institutions are not acceptable.

Technical guidance per check (structure your response around these points — do NOT copy any of this text verbatim into the output):
- Valid TLS Certificate: cert_valid=No means the cert is invalid/expired/self-signed; recommend Let's Encrypt or a trusted CA for the specific domain.
- HTTPS Redirect: http does not redirect to https; recommend 301 redirect on the same hostname before any cross-domain redirect.
- TLS 1.0 / 1.1 Disabled: tls10=Yes means insecure legacy protocols are active (POODLE, BEAST, RFC 8996 deprecated); recommend disabling them in server config.
- SSLv3 Disabled: sslv3=Yes means SSLv3 is active (POODLE); recommend disabling immediately.
- TLS 1.3 Supported: tls13=No means only older TLS versions available; recommend enabling TLS 1.3 in server config.
- HTTPS Grade A or Better: grade not in A+/A means TLS configuration weaknesses; recommend Qualys SSL Labs audit and Mozilla TLS configuration.
- HSTS Header Present (HTTPS): hsts=No at the TLS endpoint; recommend Strict-Transport-Security: max-age=15768000 with includeSubDomains.
- OCSP Stapling: ocsp=No; recommend enabling ssl_stapling in Nginx or equivalent.
- CAA Records: caa=No; recommend adding CAA DNS records to restrict which CAs may issue certificates.
- Certificate Transparency: ct=No; recommend verifying CT submission at crt.sh.
- HTTP/2 Support: http2=No; recommend enabling HTTP/2 in server config.
- Strict-Transport-Security (headers scan): header missing; recommend max-age=15768000 and consider hstspreload.org.
- Content Security Policy (CSP): missing → recommend default-src 'self', restrict script-src, object-src 'none'. Unsafe (unsafe-inline/data:/broad https:) → recommend removing those unsafe directives.
- X-Frame-Options: missing; recommend DENY or SAMEORIGIN, or CSP frame-ancestors.
- X-Content-Type-Options: missing; recommend nosniff.
- Referrer Policy: missing or unsafe value; recommend strict-origin-when-cross-origin or stricter.
- Permissions Policy: missing; recommend disabling unused features (geolocation, microphone, camera).
- Cross-Origin-Opener-Policy: missing; recommend same-origin.
- Cross-Origin-Embedder-Policy: missing; recommend require-corp with COOP same-origin.
- Cross-Origin-Resource-Policy: missing; recommend same-origin or same-site.
- Access-Control-Allow-Origin (CORS): wildcard or overly permissive; recommend restricting to specific trusted origins.
- X-XSS-Protection: missing or non-zero; recommend setting to 0 to disable the deprecated auditor.
- Set-Cookie Security: cookies lack Secure/HttpOnly/SameSite; recommend adding those attributes.
- DNSSEC Signed: status=Missing/Unsigned; recommend enabling DNSSEC at registrar with algorithm 13 or 15.
- DNSSEC Algorithm Strength: weak algorithm (score below 80); recommend migrating to algorithm 13 (ECDSA P-256) or 15 (Ed25519).
- NSEC3 Used (Not NSEC): NSEC in use; recommend switching to NSEC3 to prevent zone enumeration.
"""

# Example-based schema — using real example values prevents the model from
# copying placeholders like <0-100> or "Critical|High|..." literally.
JSON_SCHEMA = """{
  "risk_level": "COMPUTE_FROM_SCORE",
  "risk_score": COMPUTE_INTEGER_0_TO_100,
  "executive_summary": "Two sentences in English summarising the key risks for non-technical leadership.",
  "findings": [
    {
      "test": "Content Security Policy (CSP)",
      "dimension": "HEADERS",
      "score_impact": -25,
      "passed": false,
      "reason": "Example University's website at example.edu has a Content-Security-Policy header that contains 'unsafe-inline' in script-src (csp=Unsafe from scan data), negating XSS protection by allowing execution of arbitrary inline scripts.",
      "recommendation": "Remove 'unsafe-inline' from script-src on example.edu; replace with specific trusted origins or use nonce-based CSP; also set object-src 'none' and base-uri 'self'."
    }
  ],
  "top_recommendations": ["Specific priority action 1 referencing the institution name and domain.", "Specific priority action 2.", "Specific priority action 3."],
  "compliance_notes": "Brief NIS2 or GDPR note in English, or empty string."
}
Compute risk_score and risk_level from the failing checks list provided in the user message.
Return ONLY the JSON object. Start with {, end with }. No markdown, no comments, no wrapper keys."""

USER_PROMPT_TEMPLATE = """HEI: {hei_name} | Country: {country} | Category: {category} | Domain: {url}

HTTPS: grade={https_grade} score={https_score} cert_valid={cert_valid} tls13={tls13} tls12={tls12} tls10={tls10} sslv3={sslv3} hsts={hsts} ocsp={ocsp} caa={caa} ct={ct} http2={http2}

HEADERS: score={headers_score} hsts={hdr_hsts} csp={hdr_csp} xfo={hdr_xfo} xcto={hdr_xcto} rp={hdr_rp} pp={hdr_pp} coop={hdr_coop} coep={hdr_coep} corp={hdr_corp} acao={hdr_acao} xxssp={hdr_xxssp} inconsistency={headers_inconsistency}

DNSSEC: status={dnssec_status} score={dnssec_score} algorithm={dnssec_algorithm} nsec={dnssec_nsec}

FAILING CHECKS — write a finding for each of these in your JSON output, in this exact order:
{failing_checks_list}"""


# ---------------------------------------------------------------------------
# Data loading and merging
# ---------------------------------------------------------------------------

def _load_csv_safe(path: Optional[str], label: str) -> Optional[pd.DataFrame]:
    """Load a CSV file, returning None (with a warning) if unavailable."""
    if not path:
        logger.warning("%s CSV not supplied, dimension will be omitted.", label)
        return None
    p = Path(path)
    if not p.exists():
        logger.warning("%s CSV not found at %s, dimension will be omitted.", label, p)
        return None
    df = pd.read_csv(p, dtype=str)
    logger.info("Loaded %s CSV: %d rows from %s", label, len(df), p.name)
    return df


def _infer_country_code(filename: str) -> str:
    """Infer a 2-letter country code from a source/scanner filename prefix.

    Examples: "de-2024-heis.csv" -> "DE", "PL-heis.csv" -> "PL",
    "no_https_scanner.csv" -> "NO". Mirrors the same heuristic used by the
    dashboard's frontend (csv-processor.js) so country attribution stays
    consistent end-to-end.
    """
    m = re.match(r"^([A-Za-z]{2})[-_]", Path(filename).name)
    if m:
        return m.group(1).upper()
    return Path(filename).stem[:2].upper()


def _load_all_countries_source(source_dir: Path) -> Optional[pd.DataFrame]:
    """Load and concatenate every HEI source CSV in src/source/, one per
    country, normalising each to the canonical ID/url/country schema."""
    if not source_dir.exists():
        logger.error("Source directory not found: %s", source_dir)
        return None
    files = sorted(source_dir.glob("*.csv"))
    if not files:
        logger.error("No source CSVs found in %s.", source_dir)
        return None
    frames = []
    for f in files:
        cc = _infer_country_code(f.name)
        try:
            df = pd.read_csv(f, dtype=str)
        except Exception as exc:
            logger.warning("Failed to read source CSV %s: %s", f, exc)
            continue
        df = _normalise_df(df, country=cc)
        logger.info("Loaded %d institutions from %s (country=%s)", len(df), f.name, cc)
        frames.append(df)
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True)


def _col(df: pd.DataFrame, *candidates: str, default="N/A") -> pd.Series:
    """Return the first column from candidates that exists in df."""
    for c in candidates:
        if c in df.columns:
            return df[c]
    return pd.Series([default] * len(df))


def _bool_str(val) -> str:
    """Normalise boolean-like CSV values to Yes/No."""
    if pd.isna(val):
        return "N/A"
    s = str(val).strip().lower()
    if s in ("true", "yes", "1", "active", "present", "found", "configured",
             "supported", "enabled", "valid", "ok", "signed", "stapling"):
        return "Yes"
    if s in ("false", "no", "0", "not active", "not present", "not found",
             "not configured", "not supported", "not enabled", "missing",
             "invalid", "unsigned", "absent", "none", "disabled"):
        return "No"
    return str(val)


def _compute_risk_color(risk_score) -> str:
    try:
        s = int(risk_score)
    except (ValueError, TypeError):
        return "RED"
    if s >= 70:
        return "GREEN"
    elif s >= 50:
        return "YELLOW"
    return "RED"


def _build_finding(test: str, profile: dict) -> tuple[str, str]:
    """Return (reason, recommendation) for a failing check, specific to the institution."""
    name   = profile.get("hei_name", "This institution")
    domain = profile.get("url", "the domain")
    grade  = profile.get("https_grade", "")
    h_score = profile.get("https_score", "")
    d_score = profile.get("dnssec_score", "")
    algo   = profile.get("dnssec_algorithm", "unknown algorithm")

    mapping = {
        "Valid TLS Certificate": (
            f"The TLS certificate served at {domain} ({name}) is invalid, expired, self-signed, or "
            f"untrusted, causing browser security warnings that prevent users from accessing the site securely.",
            f"Obtain and install a valid certificate for {domain} from a trusted Certificate Authority; "
            f"Let's Encrypt provides free, automatically renewed certificates."
        ),
        "HTTPS Grade A or Better": (
            f"{name}'s TLS endpoint at {domain} received grade {grade} (score {h_score}), indicating "
            f"weak cipher suites, outdated protocol support, or other TLS configuration weaknesses.",
            f"Run an audit on {domain} via Qualys SSL Labs (https://www.ssllabs.com/ssltest/); "
            f"disable weak ciphers, enable TLS 1.3, and follow Mozilla's recommended TLS configuration "
            f"(https://ssl-config.mozilla.org/)."
        ),
        "TLS 1.0 / 1.1 Disabled": (
            f"{name}'s server at {domain} accepts connections over TLS 1.0 or TLS 1.1 — protocols "
            f"deprecated by RFC 8996 and known to be vulnerable to POODLE and BEAST attacks.",
            f"Disable TLS 1.0 and TLS 1.1 in {domain}'s web server TLS configuration; "
            f"retain only TLS 1.2 and TLS 1.3."
        ),
        "SSLv3 Disabled": (
            f"{name}'s server at {domain} still supports SSLv3, a critically insecure protocol "
            f"vulnerable to the POODLE attack that must not be used in any production environment.",
            f"Disable SSLv3 immediately in {domain}'s server configuration; "
            f"all modern clients have dropped SSLv3 support."
        ),
        "TLS 1.3 Supported": (
            f"{name}'s server at {domain} does not support TLS 1.3, denying users the security "
            f"and performance improvements of the current TLS standard.",
            f"Enable TLS 1.3 on {domain}'s web server (requires OpenSSL 1.1.1+ or equivalent); "
            f"it is supported by all modern web servers and browsers."
        ),
        "HTTPS Redirect": (
            f"{name}'s website at {domain} does not redirect HTTP traffic to HTTPS, allowing "
            f"unencrypted connections and preventing HSTS from being established in browsers.",
            f"Configure {domain}'s web server to issue an HTTP 301 redirect from port 80 to HTTPS "
            f"on the same hostname before any cross-domain redirect."
        ),
        "HSTS Header Present (HTTPS)": (
            f"The TLS endpoint for {domain} ({name}) does not return a Strict-Transport-Security "
            f"header, so browsers cannot enforce HTTPS-only connections for this domain.",
            f"Add 'Strict-Transport-Security: max-age=15768000' to all HTTPS responses from {domain}; "
            f"add 'includeSubDomains' once all subdomains also support HTTPS."
        ),
        "OCSP Stapling": (
            f"{name}'s server at {domain} does not staple OCSP revocation responses, forcing "
            f"browsers to make separate real-time revocation requests that add latency and expose "
            f"user activity to the CA's OCSP responder.",
            f"Enable OCSP stapling on {domain}'s web server "
            f"(e.g. 'ssl_stapling on; ssl_stapling_verify on;' in Nginx)."
        ),
        "CAA Records": (
            f"No DNS Certification Authority Authorization (CAA) records are published for {domain} "
            f"({name}), allowing any Certificate Authority to issue certificates for this domain "
            f"without restriction.",
            f"Add CAA DNS records for {domain} specifying permitted CAs, e.g.: "
            f"'0 issue \"letsencrypt.org\"; 0 issuewild \"letsencrypt.org\"'."
        ),
        "Certificate Transparency": (
            f"The TLS certificate for {domain} ({name}) is not logged in a public Certificate "
            f"Transparency log, making it harder to detect mis-issued certificates for this domain.",
            f"Verify CT submission for {domain} at https://crt.sh/?q={domain}; "
            f"ensure the certificate is issued by a CA that automatically submits to CT logs."
        ),
        "HTTP/2 Support": (
            f"{name}'s server at {domain} does not support HTTP/2, missing header compression "
            f"and connection multiplexing that reduce page load times.",
            f"Enable HTTP/2 in {domain}'s web server configuration; "
            f"it is natively supported by all modern servers when TLS is active."
        ),
        "Strict-Transport-Security": (
            f"{name}'s website at {domain} does not send a Strict-Transport-Security header, "
            f"leaving it vulnerable to SSL-stripping attacks that silently downgrade HTTPS to HTTP.",
            f"Add 'Strict-Transport-Security: max-age=15768000; includeSubDomains' to all responses "
            f"from {domain}; after validation, consider submitting to https://hstspreload.org/."
        ),
        "Content Security Policy (CSP)": (
            f"{name}'s website at {domain} does not serve a Content-Security-Policy header, "
            f"providing no browser-level protection against cross-site scripting (XSS) attacks.",
            f"Deploy a Content-Security-Policy on {domain}: start with "
            f"'default-src \\'self\\'', restrict script-src to trusted origins, "
            f"and set 'object-src \\'none\\'' and 'base-uri \\'self\\''."
        ),
        "X-Frame-Options": (
            f"{name}'s website at {domain} lacks an X-Frame-Options header or CSP frame-ancestors "
            f"directive, making it possible to embed the page in a malicious iframe for clickjacking.",
            f"Add 'X-Frame-Options: DENY' (or SAMEORIGIN if same-origin framing is needed) "
            f"to all responses from {domain}."
        ),
        "X-Content-Type-Options": (
            f"{name}'s website at {domain} does not set the X-Content-Type-Options header, "
            f"allowing browsers to MIME-sniff responses in ways that can enable script injection.",
            f"Add 'X-Content-Type-Options: nosniff' to all HTTP responses from {domain}."
        ),
        "Referrer Policy": (
            f"{name}'s website at {domain} has no Referrer-Policy header; browsers send the full "
            f"URL as a Referer to third parties by default, potentially leaking internal paths "
            f"and query parameters.",
            f"Add 'Referrer-Policy: strict-origin-when-cross-origin' to all responses from {domain}; "
            f"use 'no-referrer' or 'same-origin' for stricter privacy."
        ),
        "Permissions Policy": (
            f"{name}'s website at {domain} does not set a Permissions-Policy header, leaving "
            f"browser features such as camera, microphone, and geolocation ungoverned for "
            f"third-party embedded content.",
            f"Add a Permissions-Policy header to {domain} that disables unused features, e.g.: "
            f"'Permissions-Policy: geolocation=(), microphone=(), camera=()'."
        ),
        "Cross-Origin-Opener-Policy": (
            f"{name}'s website at {domain} does not set a Cross-Origin-Opener-Policy header, "
            f"leaving the browsing context open to cross-origin window references exploitable "
            f"via Spectre-like side-channel attacks.",
            f"Add 'Cross-Origin-Opener-Policy: same-origin' to all responses from {domain} "
            f"to isolate the browsing context from cross-origin documents."
        ),
        "Cross-Origin-Embedder-Policy": (
            f"{name}'s website at {domain} does not set a Cross-Origin-Embedder-Policy header, "
            f"preventing cross-origin isolation and the use of security-sensitive APIs.",
            f"Add 'Cross-Origin-Embedder-Policy: require-corp' together with "
            f"'Cross-Origin-Opener-Policy: same-origin' to {domain} to enable cross-origin isolation."
        ),
        "Cross-Origin-Resource-Policy": (
            f"{name}'s website at {domain} has no Cross-Origin-Resource-Policy header, allowing "
            f"any third-party site to load its resources and exploit them in cross-origin attacks.",
            f"Add 'Cross-Origin-Resource-Policy: same-origin' (or 'same-site') to {domain} "
            f"to restrict how cross-origin documents load its resources."
        ),
        "Access-Control-Allow-Origin (CORS)": (
            # Wildcard branch: header is present AND config contains "*"
            # Absent branch: header is not present (presence = "False", "No", etc.)
            # Use _bool_str to normalise the raw presence value before comparing.
            (
                f"{name}'s server at {domain} has Access-Control-Allow-Origin set to wildcard "
                f"(config={profile.get('hdr_acao_cfg', '*')}), exposing authenticated responses "
                f"to cross-origin requests from any website."
            ) if _bool_str(str(profile.get("hdr_acao", "")).strip()) == "Yes"
               and "*" in str(profile.get("hdr_acao_cfg", "")).strip()
            else (
                f"{name}'s website at {domain} does not set an Access-Control-Allow-Origin header "
                f"(presence={profile.get('hdr_acao', 'False')}). Without an explicit CORS policy, "
                f"browsers block all cross-origin requests to other origins that this site serves."
            ),
            (
                f"Restrict the Access-Control-Allow-Origin header on {domain} to specific trusted "
                f"origins; never use '*' for authenticated or sensitive endpoints."
            ) if _bool_str(str(profile.get("hdr_acao", "")).strip()) == "Yes"
               and "*" in str(profile.get("hdr_acao_cfg", "")).strip()
            else (
                f"If {domain} serves APIs or resources to external domains, add an explicit "
                f"Access-Control-Allow-Origin header listing only trusted origins. "
                f"If no cross-origin access is needed, this is intentional - the browser "
                f"same-origin policy already protects the site by default."
            ),
        ),
        "X-XSS-Protection": (
            f"{name}'s website at {domain} does not set 'X-XSS-Protection: 0'; the deprecated "
            f"browser XSS auditor should be explicitly disabled to prevent it from introducing "
            f"vulnerabilities in older browsers.",
            f"Set 'X-XSS-Protection: 0' on {domain} to disable the deprecated auditor "
            f"and rely on a strong Content-Security-Policy for XSS mitigation."
        ),
        "Set-Cookie Security": (
            f"{name}'s website at {domain} sets cookies with a "
            f"{'weak' if str(profile.get('hdr_sc_cfg','')).strip().lower() == 'weak' else 'missing'} "
            f"security configuration (set-cookie_config={profile.get('hdr_sc_cfg','?')}), "
            f"lacking one or more of the Secure, HttpOnly, or SameSite attributes that protect "
            f"session tokens from interception and cross-site request forgery.",
            f"Add Secure, HttpOnly, and SameSite=Strict (or Lax) attributes to all cookies "
            f"set by {domain}, and ensure all cookie transmission occurs over HTTPS."
        ),
        "DNSSEC Signed": (
            f"DNSSEC is not enabled for {domain} ({name}), leaving DNS responses for this domain "
            f"vulnerable to cache-poisoning and spoofing attacks that could silently redirect "
            f"users to malicious servers.",
            f"Enable DNSSEC signing for {domain} at the DNS registrar or authoritative nameserver; "
            f"prefer algorithm 13 (ECDSA P-256) or algorithm 15 (Ed25519) for new deployments."
        ),
        "DNSSEC Algorithm Strength": (
            f"{name}'s domain {domain} uses a weak DNSSEC signing algorithm "
            f"(current: {algo}, score: {d_score}), reducing resistance to cryptographic attacks "
            f"on the DNS chain of trust.",
            f"Migrate {domain}'s DNSSEC signing to algorithm 13 (ECDSA P-256) or "
            f"algorithm 15 (Ed25519); coordinate the rollover with the DNS registrar to avoid "
            f"validation failures."
        ),
        "NSEC3 Used (Not NSEC)": (
            f"{name}'s DNS zone for {domain} uses NSEC for denial-of-existence, enabling "
            f"zone enumeration by walking the NSEC chain and exposing all hostnames in the zone.",
            f"Switch {domain}'s DNS zone from NSEC to NSEC3 (with opt-out disabled) "
            f"to prevent zone walking and hostname enumeration."
        ),
    }
    return mapping.get(
        test,
        (
            f"{name} ({domain}) failed the '{test}' security check.",
            f"Review and remediate the '{test}' configuration for {domain}.",
        ),
    )


def _rule_based_analysis(profile: dict) -> dict:
    findings = []
    score = 100

    def _check(cond: bool, test: str, dim: str, impact: int):
        nonlocal score
        if not cond:
            return
        score = max(0, score + impact)
        reason, rec = _build_finding(test, profile)
        findings.append({
            "test": test, "dimension": dim, "score_impact": impact,
            "passed": False, "reason": reason, "recommendation": rec,
        })

    def _present(val) -> bool:
        return str(val).strip().lower() in ("yes", "present", "true", "1")

    def _absent(val) -> bool:
        return not _present(val) and str(val).strip().lower() not in ("not scanned", "n/a", "")

    def _scanned(val) -> bool:
        return str(val).strip().lower() not in ("not scanned", "n/a", "")

    # HTTPS dimension
    if _scanned(profile.get("https_grade", "")):
        _check(str(profile.get("cert_valid", "")).strip() == "No",
               "Valid TLS Certificate", "HTTPS", -20)
        _check(str(profile.get("http_redirect", "")).strip() == "No",
               "HTTPS Redirect", "HTTPS", -10)
        _check(str(profile.get("https_grade", "")).strip().upper() not in ("A+", "A"),
               "HTTPS Grade A or Better", "HTTPS", -15)
        _check(str(profile.get("tls10", "")).strip() == "Yes",
               "TLS 1.0 / 1.1 Disabled", "HTTPS", -10)
        _check(str(profile.get("sslv3", "")).strip() == "Yes",
               "SSLv3 Disabled", "HTTPS", -15)
        _check(str(profile.get("tls13", "")).strip() == "No",
               "TLS 1.3 Supported", "HTTPS", -5)
        _check(str(profile.get("hsts", "")).strip() == "No",
               "HSTS Header Present (HTTPS)", "HTTPS", -10)
        _check(str(profile.get("ocsp", "")).strip() == "No",
               "OCSP Stapling", "HTTPS", -5)
        _check(str(profile.get("caa", "")).strip() == "No",
               "CAA Records", "HTTPS", -5)
        _check(str(profile.get("ct", "")).strip() == "No",
               "Certificate Transparency", "HTTPS", -3)
        _check(str(profile.get("http2", "")).strip() == "No",
               "HTTP/2 Support", "HTTPS", -2)

    # HEADERS dimension
    if _scanned(profile.get("headers_score", "")):
        _check(_absent(profile.get("hdr_hsts", "")),
               "Strict-Transport-Security", "HEADERS", -20)
        _check(_absent(profile.get("hdr_csp", "")),
               "Content Security Policy (CSP)", "HEADERS", -25)
        _check(_absent(profile.get("hdr_xfo", "")),
               "X-Frame-Options", "HEADERS", -10)
        _check(_absent(profile.get("hdr_xcto", "")),
               "X-Content-Type-Options", "HEADERS", -10)
        _check(_absent(profile.get("hdr_rp", "")),
               "Referrer Policy", "HEADERS", -5)
        _check(_absent(profile.get("hdr_pp", "")),
               "Permissions Policy", "HEADERS", -5)
        _check(_absent(profile.get("hdr_coop", "")),
               "Cross-Origin-Opener-Policy", "HEADERS", -5)
        _check(_absent(profile.get("hdr_coep", "")),
               "Cross-Origin-Embedder-Policy", "HEADERS", -3)
        _check(_absent(profile.get("hdr_corp", "")),
               "Cross-Origin-Resource-Policy", "HEADERS", -3)
        # ACAO: flag wildcard (high risk) and absent (advisory — no explicit CORS policy).
        # hdr_acao holds the presence field ("True"/"False"); hdr_acao_cfg holds the config
        # value (e.g. "*", "https://trusted.example.com", "Missing").
        # Use _present() for absence detection so "False" values are handled correctly —
        # the old hardcoded ("not found", "not configured", "") list missed raw "False".
        _hdr_acao_pres = str(profile.get("hdr_acao", "")).strip()
        _hdr_acao_cfg  = str(profile.get("hdr_acao_cfg", "")).strip()
        _acao_wildcard = _present(_hdr_acao_pres) and "*" in _hdr_acao_cfg
        _acao_absent   = not _present(_hdr_acao_pres) and _scanned(_hdr_acao_pres)
        _check(
            _acao_wildcard or (_acao_absent and _scanned(profile.get("headers_score", ""))),
            "Access-Control-Allow-Origin (CORS)", "HEADERS", -8 if _acao_wildcard else -3,
        )
        # X-XSS-Protection: flag if absent (should be set to 0 to explicitly disable)
        _check(_absent(profile.get("hdr_xxssp", "")),
               "X-XSS-Protection", "HEADERS", -5)
        # Set-Cookie: flag when cookies are present but not strongly configured
        # (config = "Weak" means some flags missing; "Missing" means none)
        _check(
            profile.get("hdr_sc_pres", "") == "Yes"
            and str(profile.get("hdr_sc_cfg", "")).strip().lower() in ("weak", "missing"),
            "Set-Cookie Security", "HEADERS", -10,
        )

    # DNSSEC dimension
    if _scanned(profile.get("dnssec_status", "")):
        _check(str(profile.get("dnssec_status", "")).strip().lower() in ("missing", "unsigned", "no"),
               "DNSSEC Signed", "DNSSEC", -15)
        try:
            ds = float(profile.get("dnssec_score", 100))
            _check(ds < 80, "DNSSEC Algorithm Strength", "DNSSEC", -5)
        except (ValueError, TypeError):
            pass
        _check(str(profile.get("dnssec_nsec", "")).strip().upper() == "NSEC",
               "NSEC3 Used (Not NSEC)", "DNSSEC", -3)

    if score >= 85:
        risk_level = "Minimal"
    elif score >= 70:
        risk_level = "Low"
    elif score >= 50:
        risk_level = "Medium"
    elif score >= 30:
        risk_level = "High"
    else:
        risk_level = "Critical"

    sorted_findings = sorted(findings, key=lambda f: f["score_impact"])
    top3 = [f["recommendation"] for f in sorted_findings[:3]]

    compliance = (
        "Under NIS2 Directive (EU 2022/2555), higher education institutions providing essential "
        "services must implement appropriate technical measures to manage cybersecurity risks. "
        "The identified weaknesses should be remediated as part of a baseline security programme."
        if findings else ""
    )

    hei_name = profile.get("hei_name", "")
    return {
        "risk_level": risk_level,
        "risk_score": score,
        "executive_summary": (
            f"{hei_name} has {len(findings)} failing security check(s) with a computed risk score "
            f"of {score}/100 ({risk_level}). "
            "Immediate action is recommended for the highest-impact findings listed below."
            if findings else
            f"{hei_name} passed all evaluated security checks with a score of {score}/100 ({risk_level})."
        ),
        "findings": findings,
        "top_recommendations": top3,
        "compliance_notes": compliance,
        "_source": "rule_based",
    }


def _index_by_id(df: Optional[pd.DataFrame], score_col: Optional[str]) -> Optional[pd.DataFrame]:
    """Index a scanner-result DataFrame by canonical institution ID for O(1)
    lookups, keeping one row per ID (prefers a valid score, then the most
    recent assessment_datetime) so multi-country files — where IDs are
    globally unique thanks to _normalise_df — merge in linear time instead
    of the old O(institutions x rows) per-row table scan."""
    if df is None or df.empty or "ID" not in df.columns:
        return None
    d = df.copy()
    d["ID"] = d["ID"].astype(str).str.strip()
    if score_col and score_col in d.columns:
        valid = pd.to_numeric(d[score_col], errors="coerce").notna()
    else:
        valid = pd.Series(True, index=d.index)
    d["_valid"] = valid.astype(int)
    d["_dt"] = d["assessment_datetime"] if "assessment_datetime" in d.columns else ""
    d = d.sort_values(["_valid", "_dt"], ascending=[False, False])
    d = d.drop_duplicates(subset=["ID"], keep="first")
    return d.set_index("ID")


def build_merged_profiles(
    https_df: Optional[pd.DataFrame],
    headers_df: Optional[pd.DataFrame],
    dnssec_df: Optional[pd.DataFrame],
    source_df: pd.DataFrame,
) -> list[dict]:
    """
    Merge the three scanner result DataFrames with the source HEI list by
    canonical institution ID. Inputs are expected to already carry the
    normalised "ID" column from _normalise_df (globally unique across
    countries), which is what makes it safe to run this over every country
    at once instead of one country's CSVs per invocation.
    Returns a list of dicts, one per institution, ready for prompt building.
    """
    https_idx   = _index_by_id(https_df,   "final_score")
    headers_idx = _index_by_id(headers_df, "final_score")
    dnssec_idx  = _index_by_id(dnssec_df,  "score")

    profiles = []

    for _, hei in source_df.iterrows():
        hei_id   = str(hei.get("ID", "")).strip()
        name     = str(hei.get("Name", "Unknown"))
        url      = str(hei.get("url", ""))
        category = str(hei.get("Category", ""))
        country  = str(hei.get("country", "")).strip()

        h_row  = https_idx.loc[hei_id]   if https_idx   is not None and hei_id in https_idx.index   else None
        sh_row = headers_idx.loc[hei_id] if headers_idx is not None and hei_id in headers_idx.index else None
        d_row  = dnssec_idx.loc[hei_id]  if dnssec_idx  is not None and hei_id in dnssec_idx.index  else None

        def _g(row, *cols, default="N/A"):
            if row is None:
                return "Not scanned"
            for c in cols:
                if c in row.index and not pd.isna(row[c]):
                    return row[c]
            return default

        profile = {
            "hei_id":       hei_id,
            "hei_name":     name,
            "url":          url,
            "category":     category,
            "country":      country,
            # HTTPS — column names from no_https_scanner.csv
            "https_grade":  _g(h_row, "grade"),
            "https_score":  _g(h_row, "final_score", "score"),
            "cert_valid":   _bool_str(_g(h_row, "valid_certificate")),
            "tls13":        _bool_str(_g(h_row, "TLS1_3", "TLSv1_3")),
            "tls12":        _bool_str(_g(h_row, "TLS1_2", "TLSv1_2")),
            "tls10":        _bool_str(_g(h_row, "TLS1",   "TLSv1")),
            "sslv3":        _bool_str(_g(h_row, "SSLv3")),
            "hsts":         _bool_str(_g(h_row, "strict-transport-security_presence", "HSTS")),
            "ocsp":         _bool_str(_g(h_row, "ocsp_stapling")),
            "caa":          _bool_str(_g(h_row, "dns_caa", "CAA")),
            "ct":           _bool_str(_g(h_row, "certificate_transparency")),
            "http2":        _bool_str(_g(h_row, "ALPN_HTTP2", "HTTP2")),
            # Headers — column names from sh_final_result_with_scores_unique_hei.csv
            "headers_score":         _g(sh_row, "final_score", "header_avg_score_btw_platforms", "score"),
            "http_redirect":          _bool_str(_g(sh_row, "redirected_to_https")),
            "hdr_hsts":              _g(sh_row, "strict-transport-security_presence"),
            "hdr_csp":               _g(sh_row, "content-security-policy_presence"),
            "hdr_xfo":               _g(sh_row, "x-frame-options_presence"),
            "hdr_xcto":              _g(sh_row, "x-content-type-options_presence"),
            "hdr_rp":                _g(sh_row, "referrer-policy_presence"),
            "hdr_pp":                _g(sh_row, "permissions-policy_presence", "Permissions-Policy"),
            "hdr_coop":              _g(sh_row, "cross-origin-opener-policy_presence"),
            "hdr_coep":              _g(sh_row, "cross-origin-embedder-policy_presence"),
            "hdr_corp":              _g(sh_row, "cross-origin-resource-policy_presence"),
            "hdr_acao":              _g(sh_row, "access-control-allow-origin_presence"),
            "hdr_acao_cfg":          _g(sh_row, "access-control-allow-origin_config"),
            "hdr_xxssp":             _g(sh_row, "x-xss-protection_presence"),
            "hdr_sc_pres":           _bool_str(_g(sh_row, "set-cookie_presence")),
            "hdr_sc_cfg":            _g(sh_row, "set-cookie_config"),
            "headers_inconsistency": _bool_str(_g(sh_row, "critical_header_inconsistency_between_platforms",
                                                          "header_inconsistency_between_platforms")),
            # DNSSEC — column names from no_dnssec_scanner.csv
            "dnssec_status":    _g(d_row, "dnssec_status"),
            "dnssec_score":     _g(d_row, "score"),
            "dnssec_algorithm": _g(d_row, "algorithms"),
            "dnssec_nsec":      _g(d_row, "non_existence_proof_method"),
        }
        profiles.append(profile)

    return profiles


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _format_failing_checks(profile: dict) -> str:
    """Pre-compute failing checks and format them for the LLM prompt."""
    # Map each test name to the most relevant scan-value label for context
    scan_val = {
        "Valid TLS Certificate":              f"cert_valid={profile.get('cert_valid')}",
        "HTTPS Redirect":                     f"redirected_to_https={profile.get('http_redirect', 'N/A')}",
        "TLS 1.3 Supported":                  f"tls13={profile.get('tls13')}",
        "TLS 1.0 / 1.1 Disabled":            f"tls10={profile.get('tls10')}",
        "SSLv3 Disabled":                     f"sslv3={profile.get('sslv3')}",
        "HTTPS Grade A or Better":            f"grade={profile.get('https_grade')}",
        "HSTS Header Present (HTTPS)":        f"hsts={profile.get('hsts')}",
        "OCSP Stapling":                      f"ocsp={profile.get('ocsp')}",
        "CAA Records":                        f"caa={profile.get('caa')}",
        "Certificate Transparency":           f"ct={profile.get('ct')}",
        "HTTP/2 Support":                     f"http2={profile.get('http2')}",
        "Strict-Transport-Security":          f"hdr_hsts={profile.get('hdr_hsts')}",
        "Content Security Policy (CSP)":      f"csp={profile.get('hdr_csp')}",
        "X-Frame-Options":                    f"xfo={profile.get('hdr_xfo')}",
        "X-Content-Type-Options":             f"xcto={profile.get('hdr_xcto')}",
        "Referrer Policy":                    f"rp={profile.get('hdr_rp')}",
        "Permissions Policy":                 f"pp={profile.get('hdr_pp')}",
        "Cross-Origin-Opener-Policy":         f"coop={profile.get('hdr_coop')}",
        "Cross-Origin-Embedder-Policy":       f"coep={profile.get('hdr_coep')}",
        "Cross-Origin-Resource-Policy":       f"corp={profile.get('hdr_corp')}",
        "Access-Control-Allow-Origin (CORS)": (
            f"acao=wildcard, config={profile.get('hdr_acao_cfg', 'Missing')}"
            if "*" in str(profile.get("hdr_acao_cfg", "")).strip()
            else f"acao=absent (presence={profile.get('hdr_acao', 'False')})"
        ),
        "X-XSS-Protection":                   f"xxssp={profile.get('hdr_xxssp')}",
        "Set-Cookie Security":                f"set_cookie=Present, config={profile.get('hdr_sc_cfg', 'Missing')}",
        "DNSSEC Signed":                      f"status={profile.get('dnssec_status')}",
        "DNSSEC Algorithm Strength":          f"algorithm={profile.get('dnssec_algorithm')}",
        "NSEC3 Used (Not NSEC)":              f"nsec={profile.get('dnssec_nsec')}",
    }
    rule = _rule_based_analysis(profile)
    findings = rule.get("findings", [])
    if not findings:
        return "None — all checks passed."
    lines = []
    for f in findings:
        hint = scan_val.get(f["test"], "")
        lines.append(
            f'- "{f["test"]}" ({f["dimension"]}, score_impact={f["score_impact"]}) — {hint}'
        )
    return "\n".join(lines)


def _build_prompt(profile: dict) -> str:
    return USER_PROMPT_TEMPLATE.format(
        hei_name             = profile["hei_name"],
        country              = profile.get("country") or "N/A",
        category             = profile["category"],
        url                  = profile["url"],
        https_grade          = profile["https_grade"],
        cert_valid           = profile["cert_valid"],
        tls13                = profile["tls13"],
        tls12                = profile["tls12"],
        tls10                = profile["tls10"],
        sslv3                = profile["sslv3"],
        hsts                 = profile["hsts"],
        ocsp                 = profile["ocsp"],
        caa                  = profile["caa"],
        ct                   = profile["ct"],
        http2                = profile["http2"],
        https_score          = profile["https_score"],
        headers_score        = profile["headers_score"],
        hdr_hsts             = profile["hdr_hsts"],
        hdr_csp              = profile["hdr_csp"],
        hdr_xfo              = profile["hdr_xfo"],
        hdr_xcto             = profile["hdr_xcto"],
        hdr_rp               = profile["hdr_rp"],
        hdr_pp               = profile["hdr_pp"],
        hdr_coop             = profile["hdr_coop"],
        hdr_coep             = profile["hdr_coep"],
        hdr_corp             = profile["hdr_corp"],
        hdr_acao             = profile["hdr_acao"],
        hdr_xxssp            = profile["hdr_xxssp"],
        headers_inconsistency= profile["headers_inconsistency"],
        dnssec_status        = profile["dnssec_status"],
        dnssec_score         = profile["dnssec_score"],
        dnssec_algorithm     = profile["dnssec_algorithm"],
        dnssec_nsec          = profile["dnssec_nsec"],
        failing_checks_list  = _format_failing_checks(profile),
    )


# ---------------------------------------------------------------------------
# Backend helpers
# ---------------------------------------------------------------------------

def _check_connection(url: str, api_key: Optional[str] = None, timeout: int = 8) -> bool:
    try:
        parsed = urlparse(url)
        probe = f"{parsed.scheme}://{parsed.netloc}/"
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        requests.get(probe, headers=headers, timeout=timeout)
        return True
    except requests.RequestException:
        return False


def list_models(backend: str, api_url: str, models_url: Optional[str],
                api_key: Optional[str] = None) -> list[str]:
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if backend == "ollama":
        try:
            resp = requests.get(models_url or "http://localhost:11434/api/tags",
                                headers=headers, timeout=10)
            resp.raise_for_status()
            return [m["name"] for m in resp.json().get("models", [])]
        except Exception as exc:
            logger.warning("Could not list Ollama models: %s", exc)
            return []
    else:
        if not models_url:
            parsed = urlparse(api_url)
            models_url = f"{parsed.scheme}://{parsed.netloc}/v1/models"
        try:
            resp = requests.get(models_url, headers=headers, timeout=10)
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
        except Exception as exc:
            logger.warning("Could not list models: %s", exc)
            return []


def auto_select_model(backend: str, api_url: str, models_url: Optional[str],
                      api_key: Optional[str] = None) -> Optional[str]:
    models = list_models(backend, api_url, models_url, api_key)
    if models:
        logger.info("Auto-selected model: %s", models[0])
        return models[0]
    return None


# ---------------------------------------------------------------------------
# LLM call dispatcher
# ---------------------------------------------------------------------------

def _repair_truncated_json(raw: str) -> Optional[dict]:
    """
    Attempt to recover a valid dict from a truncated or malformed JSON string.

    Handles three failure modes produced by LM Studio when context window is
    too small to fit the full model output:

    1. Trailing comma before ] or } (Illegal trailing comma before end of array)
    2. Truncation mid-value-string (open string at end of text)
    3. Truncation mid-key (Expecting property name enclosed in double quotes)
    """
    import re as re2

    text = raw.strip()

    # Step 1: remove trailing commas before ] or } using lambda (avoids back-ref encoding issues)
    text = re2.sub(r',(' + r'\s*[}\]])', lambda m: m.group(1), text)

    # Step 2: remove trailing comma at very end
    text = re2.sub(r',' + r'\s*$', '', text)

    def _close_open_containers(t):
        """Walk t, detect open strings and containers, close them."""
        openers = {"{": "}", "[": "]"}
        closers = {"}", "]"}
        stack = []
        in_str = False
        esc = False
        backslash = '\\'
        for ch in t:
            if esc:
                esc = False
                continue
            if ch == backslash:
                esc = True
                continue
            if ch == '"' and not esc:
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch in openers:
                stack.append(openers[ch])
            elif ch in closers:
                if stack and stack[-1] == ch:
                    stack.pop()
        result = t
        if in_str:
            result += '..."'
        for c in reversed(stack):
            result += c
        return result

    # Attempt 1: close as-is
    candidate = _close_open_containers(text)
    try:
        result = json.loads(candidate)
        if isinstance(result, dict):
            logger.warning('Recovered truncated JSON — some fields may be incomplete.')
            return result
    except json.JSONDecodeError:
        pass

    # Attempt 2: strip last incomplete key-value pair, then close
    stripped = re2.sub(',\\s*"[^"]*"?\\s*(?::\\s*[^,}\\]]*)?$', '', text.rstrip())
    if stripped != text.rstrip():
        candidate2 = _close_open_containers(stripped)
        try:
            result = json.loads(candidate2)
            if isinstance(result, dict):
                logger.warning('Recovered truncated JSON (stripped incomplete key) — some fields may be incomplete.')
                return result
        except json.JSONDecodeError:
            pass

    return None


def _parse_content(content: str) -> Optional[dict]:
    """
    Parse JSON from LLM response, handling:
      - Reasoning model <think>...</think> blocks (DeepSeek-R1, Qwen3-thinking)
      - Markdown ```json ... ``` fences
      - Raw JSON
      - JS-style // line comments inside JSON
      - Mixed content (JSON object followed by prose)
      - Truncated JSON caused by max_tokens limits (attempted repair)
    """
    import re
    content = content.strip()

    # Strip <think>...</think> blocks
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    # Strip markdown code fences
    if content.startswith("```"):
        parts = content.split("```")
        content = parts[1]
        if content.startswith("json"):
            content = content[4:]
        content = content.strip()

    # Extract only the JSON object: skip prose before the first '{' and strip
    # any prose the model appended after the matching closing '}'.
    brace_start = content.find("{")
    if brace_start != -1:
        depth = 0
        in_str = False
        esc = False
        end_idx = -1
        for i, ch in enumerate(content[brace_start:], start=brace_start):
            if esc:
                esc = False
                continue
            if ch == "\\" and in_str:
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
        if end_idx != -1:
            if end_idx < len(content) - 1:
                logger.warning("Stripping trailing prose after JSON closing brace.")
            content = content[brace_start:end_idx + 1]
        elif brace_start > 0:
            content = content[brace_start:]

    # Remove JS-style // line comments (invalid in JSON).
    def _strip_js_comments(text: str) -> str:
        result = []
        in_str = False
        esc = False
        i = 0
        while i < len(text):
            ch = text[i]
            if esc:
                result.append(ch)
                esc = False
                i += 1
                continue
            if ch == "\\" and in_str:
                result.append(ch)
                esc = True
                i += 1
                continue
            if ch == '"':
                in_str = not in_str
                result.append(ch)
                i += 1
                continue
            if not in_str and ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
                while i < len(text) and text[i] != "\n":
                    i += 1
                continue
            result.append(ch)
            i += 1
        return "".join(result)

    content = _strip_js_comments(content)

    # Required top-level keys that must be present for the result to be usable.
    _REQUIRED_KEYS = {"risk_level", "findings"}
    # Normalise old finding field names to the new schema.
    def _normalise_findings(d: dict) -> dict:
        for f in d.get("findings", []):
            if isinstance(f, dict):
                if "title" in f and "test" not in f:
                    f["test"] = f.pop("title")
                if "description" in f and "reason" not in f:
                    f["reason"] = f.pop("description")
                if "score" in f and "score_impact" not in f:
                    f["score_impact"] = f.pop("score")
                if "severity" in f:
                    f.pop("severity", None)
        return d

    def _unwrap(d: dict) -> dict:
        """Remove single-key envelope wrappers like {"risk_assessment": {...}}."""
        if len(d) == 1:
            inner = next(iter(d.values()))
            if isinstance(inner, dict):
                logger.warning("Unwrapping single-key envelope '%s'.", next(iter(d.keys())))
                return inner
        return d

    def _validate(d: dict) -> bool:
        """Return True if the dict contains at least the minimum required keys."""
        return bool(_REQUIRED_KEYS & d.keys())

    # Attempt clean parse
    try:
        result = json.loads(content)
        if isinstance(result, dict):
            result = _unwrap(result)
            if _validate(result):
                return _normalise_findings(result)
            logger.warning("Parsed dict missing required keys (got: %s).", list(result.keys()))
    except json.JSONDecodeError as exc:
        logger.warning("JSON parse error: %s -- attempting truncation repair.", exc)

    # Attempt repair for truncated output
    repaired = _repair_truncated_json(content)
    if repaired is not None:
        repaired = _unwrap(repaired)
        if _validate(repaired):
            return _normalise_findings(repaired)
        logger.warning("Repaired dict missing required keys (got: %s).", list(repaired.keys()))

    logger.warning("Repair failed. Raw (first 300 chars): %.300s", content)
    return None


# Keywords that identify reasoning/thinking models — these benefit from the
# <think> prefill trick to keep chain-of-thought out of the JSON output.
_REASONING_MODEL_KEYWORDS = ("deepseek-r1", "r1-", "qwq", "qwen3", "thinking")


def _is_reasoning_model(model_id: str) -> bool:
    """Return True if the model name suggests a reasoning/thinking model."""
    m = model_id.lower()
    return any(kw in m for kw in _REASONING_MODEL_KEYWORDS)


def _call_openai(prompt: str, api_url: str, model: str,
                 api_key: Optional[str], timeout: int,
                 max_tokens: Optional[int] = None) -> Optional[dict]:
    """
    Call an OpenAI-compatible endpoint (LM Studio, OpenAI, custom).

    For reasoning models (DeepSeek-R1, QwQ, Qwen3-thinking) a three-turn
    structure is used: the assistant prefill opens a <think> block so that
    chain-of-thought stays there and the final turn returns only JSON.

    For standard instruction-tuned models a simpler two-turn structure is
    used (system + user) to avoid confusing the model with a spurious
    assistant message containing a <think> tag it does not understand.

    Each call is fully stateless — no conversation history is carried over
    between institutions.
    """
    http_headers = {"Content-Type": "application/json"}
    if api_key:
        http_headers["Authorization"] = f"Bearer {api_key}"

    json_instruction = (
        "Output ONLY a valid JSON object starting with { and ending with }. "
        "No wrapper keys, no markdown fences, no comments, no extra text. "
        "Begin your response with { immediately.\n"
        + JSON_SCHEMA
    )

    reasoning = _is_reasoning_model(model)

    # Single two-turn structure for all models.
    # For reasoning models, include an explicit instruction to skip chain-of-thought.
    no_reasoning_prefix = ""
    if reasoning:
        no_reasoning_prefix = (
            "Do not use <think> tags or extended chain-of-thought. "
            "Output JSON immediately.\n\n"
        )

    merged_user = (
        no_reasoning_prefix
        + prompt
        + "\n\n"
        + json_instruction
    )

    # Some models (e.g. Mistral-7B-Instruct v0.3 with certain prompt templates)
    # only support "user" and "assistant" roles and reject "system" with a 400.
    # We detect this by attempting the request with a system message first;
    # if that fails, the retry logic will not help. Instead, we always fold
    # the system prompt into the user message as a prefix to be safe.
    full_user = SYSTEM_PROMPT + "\n\n" + merged_user
    messages = [
        {"role": "user", "content": full_user},
    ]

    # Token budget:
    # - Reasoning models (DeepSeek-R1, QwQ): hidden CoT consumes tokens even when
    #   not visible in the response. 3000 gives room for CoT + complete JSON.
    # - Standard models (Mistral, Llama, Qwen2.5): no hidden CoT. The prompt
    #   (system + user data + schema) occupies ~800-1000 tokens. With a 4096
    # Per-institution responses include institution-specific reasons and
    # recommendations for each failing check — up to ~26 findings × ~200 tokens each.
    # Default raised to 4096 to avoid truncation on institutions with many failures.
    # Enforce a minimum of 2048 so a low GUI field value can't cause truncation.
    _MIN_TOKENS = 2048
    if max_tokens is not None:
        effective_max_tokens = max(max_tokens, _MIN_TOKENS)
    elif reasoning:
        effective_max_tokens = 4096
    else:
        effective_max_tokens = 4096

    # Safety check: warn if the requested output budget looks too large for a
    # typical small context window. The user can override with --max-tokens.
    if effective_max_tokens > 6000 and not reasoning:
        logger.warning(
            "max_tokens=%d is very large. If you get 400 errors, "
            "try --max-tokens 4096 to stay within the model's context window.",
            effective_max_tokens,
        )

    payload = {
        "model":       model,
        "messages":    messages,
        "temperature": 0.2,
        "max_tokens":  effective_max_tokens,
    }

    resp = requests.post(api_url, headers=http_headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    raw_content = ""
    finish_reason = None
    if "choices" in data and data["choices"]:
        choice = data["choices"][0]
        raw_content = choice.get("message", {}).get("content", "")
        finish_reason = choice.get("finish_reason")
    elif "content" in data:
        raw_content = data["content"]

    if finish_reason and finish_reason != "stop":
        logger.warning(
            "Model stopped with finish_reason='%s' (max_tokens=%d). "
            "Response may be truncated. Consider passing --max-tokens with a higher value.",
            finish_reason, effective_max_tokens,
        )

    return _parse_content(raw_content)


def _call_ollama(prompt: str, api_url: str, model: str, timeout: int, max_tokens: Optional[int] = None) -> Optional[dict]:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
        "options": {
            # 0.6 recommended by DeepSeek for R1-series reasoning models
            "temperature": 0.6,
            **({"num_predict": max_tokens} if max_tokens is not None else {}),
        },
    }
    resp = requests.post(api_url, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    content = data.get("message", {}).get("content", "") or \
              (data.get("choices", [{}])[0].get("message", {}).get("content", ""))
    return _parse_content(content)


def call_llm(prompt: str, backend: str, api_url: str, model: str,
             api_key: Optional[str] = None,
             retries: int = 3, retry_delay: float = 5.0,
             timeout: int = 180,
             max_tokens: Optional[int] = None) -> Optional[dict]:
    api_format = BACKENDS.get(backend, {}).get("format", "openai")

    for attempt in range(1, retries + 1):
        try:
            if api_format == "ollama":
                result = _call_ollama(prompt, api_url, model, timeout, max_tokens)
            else:
                result = _call_openai(prompt, api_url, model, api_key, timeout, max_tokens)

            if result is not None:
                return result
            logger.warning("Attempt %d/%d: LLM returned unparseable response.", attempt, retries)

        except requests.exceptions.ConnectionError as exc:
            logger.error(
                "Attempt %d/%d: Cannot connect to %s at %s. "
                "Make sure the server is running. Error: %s",
                attempt, retries, backend, api_url, exc,
            )
        except requests.exceptions.Timeout:
            logger.warning("Attempt %d/%d: Request timed out (%ds).", attempt, retries, timeout)
        except requests.exceptions.HTTPError as exc:
            logger.error("Attempt %d/%d: HTTP error: %s", attempt, retries, exc)
        except Exception as exc:
            logger.error("Attempt %d/%d: Unexpected error: %s", attempt, retries, exc)

        if attempt < retries:
            wait = retry_delay * attempt
            logger.info("Retrying in %.0f seconds...", wait)
            time.sleep(wait)

    logger.error("All %d attempts failed for this institution.", retries)
    return None


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def _write_markdown(results: list[dict], output_path: Path, backend: str, model: str):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    countries = sorted({(r["profile"].get("country") or "").upper() for r in results} - {""})
    scope = ", ".join(countries) if countries else "Higher Education Institutions"
    lines = [
        "# Web Security Risk Analysis Report",
        f"**{scope} | Generated: {now}**",
        f"**Backend:** {backend} | **Model:** {model}",
        "",
        "---",
        "",
        "## Overall Risk Distribution",
        "",
    ]

    risk_counts: dict[str, int] = {}
    for r in results:
        level = r.get("llm_risk_level") or "Unknown"
        risk_counts[level] = risk_counts.get(level, 0) + 1

    lines.append("| Risk Level | Institutions |")
    lines.append("|---|---|")
    for level in ["Critical", "High", "Medium", "Low", "Minimal", "Unknown"]:
        if level in risk_counts:
            lines.append(f"| {level} | {risk_counts[level]} |")
    lines += ["", "---", ""]

    # Per-country breakdown — only meaningful when more than one country was analysed
    if len(countries) > 1:
        lines += ["## Risk Distribution by Country", ""]
        lines.append("| Country | Critical | High | Medium | Low | Minimal | Unknown | Total |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for cc in countries:
            counts: dict[str, int] = {}
            total = 0
            for r in results:
                if (r["profile"].get("country") or "").upper() != cc:
                    continue
                level = r.get("llm_risk_level") or "Unknown"
                counts[level] = counts.get(level, 0) + 1
                total += 1
            row = [cc] + [str(counts.get(level, 0)) for level in
                          ["Critical", "High", "Medium", "Low", "Minimal", "Unknown"]] + [str(total)]
            lines.append("| " + " | ".join(row) + " |")
        lines += ["", "---", ""]

    for r in results:
        profile  = r["profile"]
        analysis = r.get("llm_analysis")

        lines.append(f"## {profile['hei_id']}: {profile['hei_name']}")
        country_tag = f" | **Country:** {profile['country'].upper()}" if profile.get("country") else ""
        lines.append(f"**URL:** {profile['url']} | **Category:** {profile['category']}{country_tag}")
        lines.append("")

        if analysis is None:
            lines.append("> LLM analysis unavailable for this institution.")
            lines += ["", "---", ""]
            continue

        lines.append(
            f"**Risk Level:** {analysis.get('risk_level', 'N/A')} | "
            f"**Risk Score:** {analysis.get('risk_score', 'N/A')}/100"
        )
        lines += ["", "### Executive Summary", analysis.get("executive_summary", ""), ""]

        findings = analysis.get("findings", [])
        if findings:
            lines += ["### Findings", ""]
            # Group by dimension
            dims_order = ["HTTPS", "HEADERS", "DNSSEC"]
            by_dim: dict[str, list] = {}
            for f in findings:
                d = f.get("dimension", "Other").upper()
                by_dim.setdefault(d, []).append(f)
            # Add any dimensions not in the standard order
            for d in by_dim:
                if d not in dims_order:
                    dims_order.append(d)
            for dim in dims_order:
                if dim not in by_dim:
                    continue
                lines += [f"#### {dim}", ""]
                lines.append("| Test | Score | Reason | Recommendation |")
                lines.append("|---|---|---|---|")
                for f in by_dim[dim]:
                    test   = f.get("test", f.get("title", ""))
                    score  = f.get("score_impact", f.get("score", ""))
                    reason = f.get("reason", f.get("description", ""))
                    rec    = f.get("recommendation", "")
                    # Escape pipe characters inside cells
                    def _esc(s): return str(s).replace("|", "\\|")
                    lines.append(f"| {_esc(test)} | {score} | {_esc(reason)} | {_esc(rec)} |")
                lines.append("")

        top_recs = analysis.get("top_recommendations", [])
        if top_recs:
            lines.append("### Top Recommendations (Priority Order)")
            for i, rec in enumerate(top_recs, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        compliance = analysis.get("compliance_notes", "")
        if compliance:
            lines += ["### Compliance Notes (NIS2 / GDPR)", compliance, ""]

        lines += ["---", ""]

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Markdown report written: %s", output_path)


def _sanitise_cell(value) -> str:
    """
    Sanitise a value for CSV output:
    - Convert to string
    - Collapse internal newlines to a space (prevents row-breaking in spreadsheets)
    - Strip leading/trailing whitespace
    """
    if value is None:
        return ""
    return " ".join(str(value).split())


def _join_list(value) -> str:
    """
    Safely join a list field from LLM output.
    Handles None, strings (returned when model output is truncated), and lists.
    """
    if not value:
        return ""
    if isinstance(value, str):
        return _sanitise_cell(value)
    if isinstance(value, list):
        return " | ".join(_sanitise_cell(item) for item in value if item)
    return _sanitise_cell(value)


def _serialise_findings(findings: list) -> str:
    """Serialise findings list to a compact JSON string safe for a CSV cell."""
    if not findings:
        return "[]"
    normalised = []
    for f in findings:
        normalised.append({
            "test":           f.get("test", f.get("title", "")),
            "dimension":      f.get("dimension", ""),
            "score_impact":   f.get("score_impact", f.get("score", 0)),
            "passed":         f.get("passed", False),
            "reason":         f.get("reason", f.get("description", "")),
            "recommendation": f.get("recommendation", ""),
        })
    return json.dumps(normalised, ensure_ascii=False)


def _write_summary_csv(results: list[dict], output_path: Path):
    fieldnames = [
        # lowercase "country" so the dashboard's country-detection (which
        # looks for an explicit `row.country` column) picks it up directly,
        # matching the convention used by the multi-country headers CSV.
        "country", "HEI_ID", "HEI_Name", "Category", "URL",
        "HTTPS_Grade", "HTTPS_Score", "Headers_Score", "DNSSEC_Status", "DNSSEC_Score",
        "LLM_Risk_Level", "LLM_Risk_Score", "Risk_Color", "Analysis_Source",
        "Executive_Summary", "Top_Recommendations", "Compliance_Notes", "Findings_JSON",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            p        = r["profile"]
            analysis = r.get("llm_analysis") or {}
            try:
                writer.writerow({
                    "country":              _sanitise_cell(str(p.get("country", "")).lower()),
                    "HEI_ID":               _sanitise_cell(p.get("hei_id")),
                    "HEI_Name":             _sanitise_cell(p.get("hei_name")),
                    "Category":             _sanitise_cell(p.get("category")),
                    "URL":                  _sanitise_cell(p.get("url")),
                    "HTTPS_Grade":          _sanitise_cell(p.get("https_grade")),
                    "HTTPS_Score":          _sanitise_cell(p.get("https_score")),
                    "Headers_Score":        _sanitise_cell(p.get("headers_score")),
                    "DNSSEC_Status":        _sanitise_cell(p.get("dnssec_status")),
                    "DNSSEC_Score":         _sanitise_cell(p.get("dnssec_score")),
                    "LLM_Risk_Level":       _sanitise_cell(analysis.get("risk_level", "N/A")),
                    "LLM_Risk_Score":       _sanitise_cell(analysis.get("risk_score", "")),
                    "Risk_Color":           _compute_risk_color(analysis.get("risk_score", "")),
                    "Analysis_Source":      _sanitise_cell(analysis.get("_source", "llm")),
                    "Executive_Summary":    _sanitise_cell(analysis.get("executive_summary", "")),
                    "Top_Recommendations":  _join_list(analysis.get("top_recommendations")),
                    "Compliance_Notes":     _sanitise_cell(analysis.get("compliance_notes", "")),
                    "Findings_JSON":        _serialise_findings(analysis.get("findings", [])),
                })
            except Exception as exc:
                hei_id = p.get("hei_id", "unknown")
                logger.error("CSV write error for %s: %s", hei_id, exc)
    logger.info("Summary CSV written: %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _resolve_urls(args) -> tuple[str, Optional[str]]:
    backend_cfg = BACKENDS[args.backend]

    if args.api_url:
        parsed = urlparse(args.api_url)
        return args.api_url, f"{parsed.scheme}://{parsed.netloc}/v1/models"

    if args.backend == "lmstudio":
        base = f"http://{args.lmstudio_host}:{args.lmstudio_port}"
        return f"{base}/v1/chat/completions", f"{base}/v1/models"

    if args.backend in ("ollama", "openai"):
        return backend_cfg["default_url"], backend_cfg["models_url"]

    logger.error("--backend custom requires --api-url")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="LLM-powered security risk analysis for European HEIs (multi-country)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--backend", choices=list(BACKENDS.keys()), default="lmstudio",
                        help="LLM backend (default: lmstudio)")

    lms = parser.add_argument_group("LM Studio options")
    lms.add_argument("--lmstudio-host", default="localhost", metavar="HOST_OR_IP",
                     help="Hostname or IP of LM Studio server (default: localhost)")
    lms.add_argument("--lmstudio-port", type=int, default=1234, metavar="PORT",
                     help="LM Studio server port (default: 1234)")

    parser.add_argument("--api-url", default=None, metavar="URL",
                        help="Override full API endpoint URL")
    parser.add_argument("--api-key", default=None, metavar="KEY",
                        help="API key (required for --backend openai)")
    parser.add_argument("--model", default=None, metavar="MODEL_ID",
                        help="Model identifier. Auto-selected if omitted.")
    parser.add_argument("--list-models", action="store_true",
                        help="List available models on the backend server and exit")

    inp = parser.add_argument_group("Input CSVs (single-country / manual mode)")
    inp.add_argument("--https-csv",   default=None, metavar="PATH",
                     help="Path to HTTPS/TLS scanner result CSV")
    inp.add_argument("--headers-csv", default=None, metavar="PATH",
                     help="Path to Security Headers scanner result CSV")
    inp.add_argument("--dnssec-csv",  default=None, metavar="PATH",
                     help="Path to DNSSEC scanner result CSV")
    inp.add_argument("--source-csv",  default=None, metavar="PATH",
                     help="Path to a single HEI source CSV. Supplying this (or any of the "
                          "three CSVs above) switches to manual single-country mode instead "
                          "of --all-countries.")

    multi = parser.add_argument_group("Multi-country mode (default)")
    multi.add_argument("--all-countries", action="store_true",
                       help="Analyse every country found under src/source/ and "
                            "src/results/{https,dnssec}/latest/, plus the multi-country "
                            "headers file. This is the default whenever no --*-csv flag "
                            "above is supplied, so it rarely needs to be passed explicitly.")
    multi.add_argument("--countries", default=None, metavar="CC,CC,...",
                       help="Restrict multi-country mode to specific ISO country codes "
                            "(comma-separated, e.g. 'no,de,fr'). Default: all countries found.")
    multi.add_argument("--source-dir", default="src/source", metavar="DIR",
                       help="Directory containing one HEI source CSV per country (default: src/source)")
    multi.add_argument("--results-root", default="src/results", metavar="DIR",
                       help="Root of scanner results, expects <root>/{https,dnssec}/latest/ "
                            "and <root>/headers/latest/ (default: src/results)")

    parser.add_argument("--output-dir", default="src/results/llm_analysis", metavar="DIR")
    parser.add_argument("--limit",   type=int,   default=None, metavar="N",
                        help="Process only the first N institutions")
    parser.add_argument("--delay",   type=float, default=1.0,  metavar="SECS",
                        help="Delay between LLM calls in seconds (default: 1)")
    parser.add_argument("--timeout", type=int,   default=600,  metavar="SECS",
                        help="HTTP timeout per LLM request in seconds (default: 600). "
                             "Reasoning models such as DeepSeek-R1 may need 300-600s per institution.")
    parser.add_argument("--max-tokens", type=int, default=None, metavar="N",
                        help="Max output tokens per institution (default: 2048). "
                             "Increase to 3000-4000 if the model is being truncated mid-JSON. "
                             "Must not exceed the model's context window minus input tokens.")
    parser.add_argument("--retries", type=int,   default=3,
                        help="Retry attempts per institution (default: 3)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    api_url, models_url = _resolve_urls(args)
    backend_cfg = BACKENDS[args.backend]

    logger.info("Backend: %s | API: %s", args.backend, api_url)

    # --list-models mode
    if args.list_models:
        print(f"\nQuerying models from {args.backend} at {models_url or api_url} ...\n")
        models = list_models(args.backend, api_url, models_url, args.api_key)
        if models:
            print(f"Available models ({len(models)}):")
            for m in models:
                print(f"  {m}")
        else:
            print(f"No models found. Make sure the {args.backend} server is running.")
        return

    manual_mode = any([args.https_csv, args.headers_csv, args.dnssec_csv, args.source_csv])
    multi_mode  = args.all_countries or not manual_mode

    if backend_cfg["requires_key"] and not args.api_key:
        parser.error(f"--backend {args.backend} requires --api-key")

    # Resolve model
    model = args.model
    if model is None:
        model = backend_cfg.get("default_model")
        if model is None:
            logger.info("No model specified, querying server...")
            model = auto_select_model(args.backend, api_url, models_url, args.api_key)
        if model is None:
            logger.error(
                "Could not determine a model. Use --model or ensure the %s server "
                "is running at %s.", args.backend, api_url
            )
            sys.exit(1)
    logger.info("Model: %s", model)

    # Connectivity probe
    if not _check_connection(api_url, args.api_key):
        logger.warning("Server at %s did not respond to probe. Proceeding anyway.", api_url)

    wanted_countries = None
    if args.countries:
        wanted_countries = {c.strip().upper() for c in args.countries.split(",") if c.strip()}

    if multi_mode:
        # --- Multi-country mode: every country under src/source/, matched against
        # every per-country scanner file under src/results/{https,dnssec}/latest/
        # and the single multi-country headers file. ---
        logger.info("Multi-country mode: discovering countries under %s", args.source_dir)
        results_root = Path(args.results_root)

        source_df = _load_all_countries_source(Path(args.source_dir))
        if source_df is None:
            logger.error("No source CSVs found in %s. Supply --source-csv for manual mode.", args.source_dir)
            sys.exit(1)

        https_df   = _load_all_scanner_latest(results_root, "https",   "*_https_scanner.csv")
        dnssec_df  = _load_all_scanner_latest(results_root, "dnssec",  "*_dnssec_scanner.csv")
        headers_df = _load_latest(results_root, "headers", "sh_final_result_with_scores_unique_hei.csv")

        if wanted_countries:
            source_df = source_df[source_df["country"].str.upper().isin(wanted_countries)]
            if https_df is not None:
                https_df = https_df[https_df["country"].str.upper().isin(wanted_countries)]
            if dnssec_df is not None:
                dnssec_df = dnssec_df[dnssec_df["country"].str.upper().isin(wanted_countries)]
            if headers_df is not None and "country" in headers_df.columns:
                headers_df = headers_df[headers_df["country"].str.upper().isin(wanted_countries)]

        found = sorted(source_df["country"].dropna().str.upper().unique())
        logger.info("Countries to analyse: %s", ", ".join(found) or "none")
    else:
        # --- Manual single-country mode: explicit CSV paths. ---
        source_csv = args.source_csv
        if source_csv is None:
            candidates = sorted(Path("src/source").glob("*.csv"))
            if candidates:
                source_csv = str(candidates[0])
                logger.info("Auto-selected source CSV: %s", source_csv)
            else:
                logger.error("No source CSV found in src/source/. Supply --source-csv.")
                sys.exit(1)

        source_df = pd.read_csv(source_csv, dtype=str)
        source_df = _normalise_df(source_df, country=_infer_country_code(source_csv))

        https_df   = _load_csv_safe(args.https_csv,   "HTTPS")
        headers_df = _load_csv_safe(args.headers_csv, "Headers")
        dnssec_df  = _load_csv_safe(args.dnssec_csv,  "DNSSEC")
        cc = _infer_country_code(args.https_csv or args.headers_csv or args.dnssec_csv or source_csv)
        if https_df is not None:
            https_df = _normalise_df(https_df, country=cc)
        if headers_df is not None:
            headers_df = _normalise_df(headers_df, country=cc)
        if dnssec_df is not None:
            dnssec_df = _normalise_df(dnssec_df, country=cc)

    if args.limit:
        source_df = source_df.head(args.limit)
    logger.info("Institutions to process: %d", len(source_df))

    # Build merged profiles
    profiles = build_merged_profiles(https_df, headers_df, dnssec_df, source_df)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for i, profile in enumerate(profiles, 1):
        logger.info("[%d/%d] Analysing %s (%s)", i, len(profiles),
                    profile["hei_id"], profile["hei_name"])

        prompt   = _build_prompt(profile)
        analysis = call_llm(
            prompt      = prompt,
            backend     = args.backend,
            api_url     = api_url,
            model       = model,
            api_key     = args.api_key,
            retries     = args.retries,
            retry_delay = 5.0,
            timeout     = args.timeout,
            max_tokens  = args.max_tokens,
        )

        if analysis is None:
            analysis = _rule_based_analysis(profile)
            logger.warning("LLM failed — using rule-based fallback for %s", profile["hei_id"])
        else:
            # Supplement LLM findings with rule-based data:
            # - Add any checks the LLM omitted entirely.
            # - Fill in empty recommendation fields the LLM left blank.
            rule = _rule_based_analysis(profile)
            rule_by_test = {f["test"]: f for f in rule.get("findings", [])}
            existing = {f["test"] for f in analysis.get("findings", [])}
            added = patched = 0
            for f in analysis.get("findings", []):
                rb = rule_by_test.get(f["test"])
                if rb:
                    if not f.get("recommendation"):
                        f["recommendation"] = rb["recommendation"]
                        patched += 1
                    if not f.get("reason"):
                        f["reason"] = rb["reason"]
                        patched += 1
            for f in rule.get("findings", []):
                if f["test"] not in existing:
                    analysis.setdefault("findings", []).append(f)
                    added += 1
            if added or patched:
                logger.debug(
                    "Supplemented %d missing + patched %d empty field(s) for %s",
                    added, patched, profile["hei_id"],
                )

        results.append({
            "profile":        profile,
            "llm_analysis":   analysis,
            "llm_risk_level": analysis.get("risk_level", "N/A"),
        })

        if args.delay > 0 and i < len(profiles):
            time.sleep(args.delay)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path   = output_dir / f"risk_analysis_report_{timestamp}.md"
    csv_path  = output_dir / f"risk_analysis_summary_{timestamp}.csv"

    _write_markdown(results, md_path, args.backend, model)
    _write_summary_csv(results, csv_path)

    logger.info("Done. Markdown: %s | CSV: %s", md_path, csv_path)


if __name__ == "__main__":
    main()
