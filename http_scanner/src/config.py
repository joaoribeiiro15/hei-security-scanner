COL_RAW_RESULTS = "raw_result_http"
COL_ASSESSMENT_DATETIME = "assessment_datetime"
COL_IP = "ip"
COL_FINAL_SCORE = "final_score"
COL_GRADE = "grade"
COL_CA = "certificate_authority"
COL_CERTIFICATE_ALGORITHM = "certificate_signature_algorithm"
COL_KEY_SIZE = "key_size"
COL_OCSP_STAPLING = "ocsp_stapling"
COL_OCSP_MUST_STAPLE = "ocsp_must_staple"
COL_DNS_CAA = "dns_caa"
COL_CERTIFICATE_TRANSPARENCY = "certificate_transparency"
COL_BANNER_SERVER = "banner_server"
COL_BANNER_APPLICATION = "banner_application"
COL_HTTP_STATUS_CODE = "http_status_code"
COL_VALID_CERTIFICATE = "valid_certificate"
COL_CERT_AT_RISK = "cert_at_risk"

desired_column_order = [
    "ETER_ID", "Name", "Category", "Institution_Category_Standardized", "Member_of_European_University_alliance", "Url",
    "NUTS2", "NUTS2_Label", "NUTS3", "NUTS3_Label",
    COL_ASSESSMENT_DATETIME, COL_IP, COL_HTTP_STATUS_CODE, COL_BANNER_SERVER, COL_BANNER_APPLICATION,
    "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "NPN", "ALPN", "ALPN_HTTP2",
    COL_CERTIFICATE_ALGORITHM, COL_KEY_SIZE, COL_OCSP_STAPLING, COL_OCSP_MUST_STAPLE, COL_DNS_CAA,
    COL_CERTIFICATE_TRANSPARENCY, COL_CA, COL_VALID_CERTIFICATE, COL_CERT_AT_RISK,
    COL_FINAL_SCORE, COL_GRADE, COL_RAW_RESULTS
]

from pathlib import Path as _Path

# Resolve testssl.sh path absolutely from this file's location:
# config.py is at http_scanner/src/config.py
# testssl.sh is at http_scanner/../testssl.sh/testssl.sh
_PROJECT_ROOT = _Path(__file__).resolve().parents[2]
_TESTSSL_PATH = str(_PROJECT_ROOT / "testssl.sh" / "testssl.sh")

config = {
    "max_workers": 1,
    "test_ssl_path": _TESTSSL_PATH,
}
