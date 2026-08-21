import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scanner.cert_validation import derive_valid_certificate, derive_cert_at_risk


def _sd(**overrides):
    """Build a minimal valid serverDefaults list, then apply overrides by id."""
    base = [
        {"id": "cert_trust", "severity": "OK", "finding": "Ok via SAN (SNI mandatory)"},
        {"id": "cert_expirationStatus", "severity": "OK", "finding": "224 >= 60 days"},
        {"id": "cert_commonName_wo_SNI", "severity": "INFO", "finding": "example.com"},
        {"id": "cert_signatureAlgorithm", "severity": "OK", "finding": "ECDSA with SHA384"},
        {"id": "cert_keySize", "severity": "OK", "finding": "EC 256 bits (curve P-256)"},
    ]
    for id_, fields in overrides.items():
        for item in base:
            if item["id"] == id_:
                item.update(fields)
                break
        else:
            base.append({"id": id_, **fields})
    return base


class TestDeriveValidCertificate(unittest.TestCase):
    def test_fully_ok(self):
        self.assertTrue(derive_valid_certificate(_sd()))

    def test_cert_trust_missing(self):
        sd = [e for e in _sd() if e["id"] != "cert_trust"]
        self.assertFalse(derive_valid_certificate(sd))

    def test_cert_trust_not_ok(self):
        sd = _sd(**{"cert_trust": {"finding": "Certificate is not trusted", "severity": "CRITICAL"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_cert_trust_ok_lowercase(self):
        sd = _sd(**{"cert_trust": {"finding": "ok via SAN"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_expiration_high_valid_by_default(self):
        # HIGH = expires < 30 days but NOT yet expired; cert is still valid (at risk)
        sd = _sd(**{"cert_expirationStatus": {"severity": "HIGH", "finding": "expires < 30 days (12)"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_expiration_high_invalid_with_strict(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "HIGH", "finding": "expires < 30 days (12)"}})
        self.assertFalse(derive_valid_certificate(sd, strict_expiration=True))

    def test_expiration_critical_invalidates(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "CRITICAL", "finding": "expired"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_expiration_medium_ok_by_default(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "MEDIUM", "finding": "expires < 60 days (33)"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_expiration_medium_ok_with_strict(self):
        # strict_expiration only tightens HIGH, not MEDIUM
        sd = _sd(**{"cert_expirationStatus": {"severity": "MEDIUM", "finding": "expires < 60 days (33)"}})
        self.assertTrue(derive_valid_certificate(sd, strict_expiration=True))

    def test_expiration_missing(self):
        sd = [e for e in _sd() if e["id"] != "cert_expirationStatus"]
        self.assertFalse(derive_valid_certificate(sd))

    def test_name_mismatch_high_invalidates(self):
        sd = _sd(**{"cert_commonName_wo_SNI": {"severity": "HIGH", "finding": "mismatch.example.com"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_name_mismatch_info_ok(self):
        sd = _sd(**{"cert_commonName_wo_SNI": {"severity": "INFO", "finding": "example.com"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_name_mismatch_absent_ok(self):
        sd = [e for e in _sd() if e["id"] != "cert_commonName_wo_SNI"]
        self.assertTrue(derive_valid_certificate(sd))

    def test_sha1_signature_invalidates(self):
        sd = _sd(**{"cert_signatureAlgorithm": {"finding": "RSA with SHA1"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_md5_signature_invalidates(self):
        sd = _sd(**{"cert_signatureAlgorithm": {"finding": "RSA with MD5"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_md2_signature_invalidates(self):
        sd = _sd(**{"cert_signatureAlgorithm": {"finding": "RSA with MD2"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_sha256_signature_ok(self):
        sd = _sd(**{"cert_signatureAlgorithm": {"finding": "RSA with SHA256"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_signature_missing(self):
        sd = [e for e in _sd() if e["id"] != "cert_signatureAlgorithm"]
        self.assertFalse(derive_valid_certificate(sd))

    def test_rsa_2048_ok(self):
        sd = _sd(**{"cert_keySize": {"finding": "RSA 2048 bits (exponent is 65537)"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_rsa_4096_ok(self):
        sd = _sd(**{"cert_keySize": {"finding": "RSA 4096 bits (exponent is 65537)"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_rsa_1024_invalidates(self):
        sd = _sd(**{"cert_keySize": {"finding": "RSA 1024 bits (exponent is 65537)"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_ec_256_ok(self):
        sd = _sd(**{"cert_keySize": {"finding": "EC 256 bits (curve P-256)"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_ec_384_ok(self):
        sd = _sd(**{"cert_keySize": {"finding": "EC 384 bits (curve P-384)"}})
        self.assertTrue(derive_valid_certificate(sd))

    def test_ec_192_invalidates(self):
        sd = _sd(**{"cert_keySize": {"finding": "EC 192 bits (curve P-192)"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_key_size_unparseable_invalidates(self):
        sd = _sd(**{"cert_keySize": {"finding": "unknown key type 2048"}})
        self.assertFalse(derive_valid_certificate(sd))

    def test_key_size_missing(self):
        sd = [e for e in _sd() if e["id"] != "cert_keySize"]
        self.assertFalse(derive_valid_certificate(sd))


class TestDeriveCertAtRisk(unittest.TestCase):
    def test_ok_not_at_risk(self):
        self.assertFalse(derive_cert_at_risk(_sd()))

    def test_medium_is_at_risk(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "MEDIUM", "finding": "expires < 60 days (33)"}})
        self.assertTrue(derive_cert_at_risk(sd))

    def test_high_is_at_risk(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "HIGH", "finding": "expires < 30 days (12)"}})
        self.assertTrue(derive_cert_at_risk(sd))

    def test_finding_starts_with_expires(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "OK", "finding": "expires < 60 days"}})
        self.assertTrue(derive_cert_at_risk(sd))

    def test_missing_expiration_not_at_risk(self):
        sd = [e for e in _sd() if e["id"] != "cert_expirationStatus"]
        self.assertFalse(derive_cert_at_risk(sd))

    def test_high_valid_and_at_risk(self):
        # HIGH expiration: cert expires < 30 days but is still valid; at_risk=True
        sd = _sd(**{"cert_expirationStatus": {"severity": "HIGH", "finding": "expires < 30 days (12)"}})
        valid = derive_valid_certificate(sd)
        at_risk = valid and derive_cert_at_risk(sd)
        self.assertTrue(valid)
        self.assertTrue(at_risk)

    def test_critical_invalid_not_at_risk(self):
        # CRITICAL: cert already expired -> invalid, caller AND prevents at_risk=True
        sd = _sd(**{"cert_expirationStatus": {"severity": "CRITICAL", "finding": "expired"}})
        valid = derive_valid_certificate(sd)
        at_risk = valid and derive_cert_at_risk(sd)
        self.assertFalse(valid)
        self.assertFalse(at_risk)

    def test_medium_valid_and_at_risk(self):
        sd = _sd(**{"cert_expirationStatus": {"severity": "MEDIUM", "finding": "expires < 60 days (45)"}})
        valid = derive_valid_certificate(sd)
        at_risk = valid and derive_cert_at_risk(sd)
        self.assertTrue(valid)
        self.assertTrue(at_risk)


if __name__ == "__main__":
    unittest.main()
