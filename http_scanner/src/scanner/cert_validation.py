import logging
import re

_WEAK_SIGNATURES = ("sha1", "md5", "md2")


def _find(server_defaults, id_):
    """Return the first entry whose 'id' matches id_, or None."""
    for item in server_defaults:
        if item.get("id") == id_:
            return item
    return None


def derive_valid_certificate(server_defaults, strict_expiration=False):
    """
    Decide whether a TLS certificate is operationally valid based on the
    serverDefaults section of the testssl.sh JSON output.

    A certificate is valid when ALL of the following hold:
      1. cert_trust.finding starts with "Ok" (case-insensitive)
      2. cert_expirationStatus does NOT indicate an expired cert:
         CRITICAL always invalidates (cert already expired);
         HIGH (expires < 30 days) and MEDIUM (expires < 60 days) are
         tracked as "at risk" but do NOT invalidate unless
         strict_expiration=True (HIGH) or both flags are set (MEDIUM).
      3. cert_commonName_wo_SNI.severity != "HIGH"   (no name mismatch)
      4. cert_signatureAlgorithm.finding is not in the weak set
         (SHA1, MD5, MD2, anywhere in the string, case-insensitive)
      5. Key strength: RSA >= 2048 bits OR EC >= 256 bits
         (parsed from cert_keySize.finding, e.g.
          "RSA 2048 bits (exponent is 65537)",
          "EC 256 bits (curve P-256)")

    Default policy (strict_expiration=False): only CRITICAL severity
    (cert already expired) invalidates. HIGH (< 30 days) and MEDIUM
    (< 60 days) are flagged via derive_cert_at_risk but remain valid.
    With strict_expiration=True, HIGH also invalidates.

    If any of the required findings is missing from the JSON (None), the
    function returns False and logs a warning identifying which finding
    is missing for that target.

    References: Barreto et al., Neef, Pinto -- HEI TLS evaluation methodology.
    """
    cert_trust = _find(server_defaults, "cert_trust")
    if cert_trust is None:
        logging.warning("derive_valid_certificate: cert_trust missing from serverDefaults")
        return False
    if not cert_trust.get("finding", "").lower().startswith("ok"):
        return False

    expiration = _find(server_defaults, "cert_expirationStatus")
    if expiration is None:
        logging.warning("derive_valid_certificate: cert_expirationStatus missing from serverDefaults")
        return False
    exp_severity = expiration.get("severity", "").upper()
    if exp_severity == "CRITICAL":
        return False
    if strict_expiration and exp_severity == "HIGH":
        return False

    cn_wo_sni = _find(server_defaults, "cert_commonName_wo_SNI")
    if cn_wo_sni is not None and cn_wo_sni.get("severity", "").upper() == "HIGH":
        return False

    sig_alg = _find(server_defaults, "cert_signatureAlgorithm")
    if sig_alg is None:
        logging.warning("derive_valid_certificate: cert_signatureAlgorithm missing from serverDefaults")
        return False
    sig_finding = sig_alg.get("finding", "").lower()
    if any(weak in sig_finding for weak in _WEAK_SIGNATURES):
        return False

    key_size_entry = _find(server_defaults, "cert_keySize")
    if key_size_entry is None:
        logging.warning("derive_valid_certificate: cert_keySize missing from serverDefaults")
        return False
    key_finding = key_size_entry.get("finding", "")
    rsa_match = re.search(r"RSA\s+(\d+)\s+bits", key_finding, re.IGNORECASE)
    ec_match = re.search(r"EC\s+(\d+)\s+bits", key_finding, re.IGNORECASE)
    if rsa_match:
        if int(rsa_match.group(1)) < 2048:
            return False
    elif ec_match:
        if int(ec_match.group(1)) < 256:
            return False
    else:
        logging.warning(
            "derive_valid_certificate: cannot parse key size from: %r", key_finding
        )
        return False

    return True


def derive_cert_at_risk(server_defaults):
    """
    Return True when cert_expirationStatus severity is MEDIUM or HIGH,
    or the finding text starts with "expires <".

    Callers should AND this with valid_certificate before storing, so
    that only certs that are valid-but-expiring-soon are flagged:
        cert_at_risk = derive_cert_at_risk(sd) and derive_valid_certificate(sd)
    """
    expiration = _find(server_defaults, "cert_expirationStatus")
    if expiration is None:
        return False
    severity = expiration.get("severity", "").upper()
    finding = expiration.get("finding", "").lower()
    return severity in ("MEDIUM", "HIGH") or finding.startswith("expires <")
