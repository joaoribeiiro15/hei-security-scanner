import json
import logging
import os
import subprocess
import tempfile
import threading
from concurrent.futures.thread import ThreadPoolExecutor

import pandas as pd
from uuid import uuid4

from src import config
from src.config import config, COL_ASSESSMENT_DATETIME, COL_IP, COL_FINAL_SCORE, COL_GRADE, COL_RAW_RESULTS, COL_CA, \
    COL_CERTIFICATE_ALGORITHM, COL_KEY_SIZE, COL_OCSP_STAPLING, COL_DNS_CAA, COL_CERTIFICATE_TRANSPARENCY, \
    COL_BANNER_SERVER, COL_BANNER_APPLICATION, COL_OCSP_MUST_STAPLE, COL_VALID_CERTIFICATE, COL_CERT_AT_RISK, \
    COL_HTTP_STATUS_CODE, desired_column_order
from src.scanner.cert_validation import derive_valid_certificate, derive_cert_at_risk

final_errors = []
final_results = []
lock = threading.Lock()


def scan(file_path):
    global final_errors
    global final_results
    final_errors = []
    final_results = []
    df = pd.read_csv(file_path)
    filename = os.path.basename(file_path)
    country_code = filename[:2]
    url_column_name = next((col for col in df.columns if col.lower() == 'url'), None)
    if url_column_name is None:
        raise ValueError(f"No 'url' column found in CSV ({filename}).")

    if "error" in df.columns:
        df = df.drop(columns=["error"])

    # Resume: skip URLs already present in the results CSV from a previous successful scan.
    # Errors are intentionally NOT skipped — failed scans should always be retried.
    resume_path = os.path.join('.', 'src', 'data', 'results',
                               f"{country_code}_https_scanner.csv")
    if os.path.exists(resume_path):
        try:
            done_df = pd.read_csv(resume_path, usecols=[url_column_name])
            done_urls = set(done_df[url_column_name].dropna().str.strip())
            if done_urls:
                before = len(df)
                df = df[~df[url_column_name].str.strip().isin(done_urls)]
                skipped = before - len(df)
                if skipped:
                    logging.info(f"[https] Resume: skipping {skipped} already-scanned URLs.")
        except Exception:
            pass

    if df.empty:
        logging.info(f"[https] All URLs in {filename} already scanned. Nothing to do.")
        return

    max_workers = config.get("max_workers", 5)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_row, row, url_column_name) for index, row in df.iterrows()]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logging.error(f"Thread error in CSV ({filename}): {e}")

    if final_results:
        save(final_results, country_code)
    if final_errors:
        save(final_errors, country_code, error=True)


def scan_row(row, url_column_name):
    url = row[url_column_name]
    temp_file_path = os.path.join(tempfile.gettempdir(), f"{str(uuid4())}.json")
    test_ssl_path = config["test_ssl_path"]
    try:
        logging.info(f"Scanning URL: {row[url_column_name]}")
        result = subprocess.run(
            args=[
                test_ssl_path, '--assuming-http', '--ids-friendly', '--sneaky',
                '--connect-timeout', '30', '--openssl-timeout', '30',
                '--jsonfile-pretty', temp_file_path, url
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # hard kill after 5 minutes — prevents infinite hang on unresponsive hosts
        )
        # testssl.sh returns non-zero exit codes when it finds security
        # issues (which is expected). Instead of checking the return code,
        # verify that the JSON output file was created and contains results.
        if not os.path.exists(temp_file_path) or os.path.getsize(temp_file_path) == 0:
            err_detail = result.stderr.strip() or result.stdout.strip()[:500]
            raise RuntimeError(f"testssl.sh produced no output for {url} (exit code {result.returncode}): {err_detail}")
        with open(temp_file_path, 'r') as json_file:
            result = extract_result(json.load(json_file))
        with lock:
            final_results.append({**row.to_dict(), **result})

    except subprocess.TimeoutExpired:
        logging.error(f"Timeout scanning URL {url}: testssl.sh exceeded 5 minutes, skipping.")
        with lock:
            final_errors.append({**row.to_dict(), 'error': 'timeout: testssl.sh exceeded 300s'})
    except Exception as e:
        logging.error(f"Error scanning URL {url}: {e}")
        with lock:
            final_errors.append({**row.to_dict(), 'error': str(e)})

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def extract_result(raw_json):
    results = []
    scan_results = raw_json.get('scanResult', [])

    if not isinstance(scan_results, list):
        scan_results = [scan_results]

    for scan_result in scan_results:
        result = {}

        result.update({COL_ASSESSMENT_DATETIME: pd.Timestamp.now()})
        result.update({COL_IP: scan_result.get("ip", None)})
        result.update({**extract_protocols(scan_result.get("protocols", []))})
        result.update({**extract_certificate_info(scan_result.get("serverDefaults", []))})
        result.update({**extract_header_response(scan_result.get("headerResponse", []))})
        rating_data = extract_rating(scan_result.get("rating", []))
        result.update({**rating_data})
        result.update({COL_RAW_RESULTS: json.dumps(raw_json)})

        results.append((result, rating_data.get("final_score", float('inf'))))
    worst_result = min(results, key=lambda x: x[1])[0]

    return worst_result


def extract_header_response(headers):
    header_response = {}
    for header in headers:
        header_name = header.get("id", None)
        if header_name:
            if header_name == "banner_server":
                header_response.update({COL_BANNER_SERVER: header.get("finding", None)})
            elif header_name == "banner_application":
                header_response.update({COL_BANNER_APPLICATION: False if header.get("finding",
                                                                                    None) == "No application banner found" else True})
            elif header_name == "HTTP_status_code":
                header_response.update({COL_HTTP_STATUS_CODE: header.get("finding", None)})
    return header_response


def extract_certificate_info(certificates_infos):
    certificate_info = {}
    for certificate in certificates_infos:
        id_ = certificate.get("id", None)
        if id_ == "cert_caIssuers":
            certificate_info.update({COL_CA: certificate.get("finding", None)})
        elif id_ == "cert_signatureAlgorithm":
            certificate_info.update({COL_CERTIFICATE_ALGORITHM: certificate.get("finding", None)})
        elif id_ == "cert_keySize":
            certificate_info.update({COL_KEY_SIZE: certificate.get("finding", None)})
        elif id_ == "OCSP_stapling":
            certificate_info.update(
                {COL_OCSP_STAPLING: False if "not" in certificate.get("finding", "").lower() else True})
        elif id_ == "cert_mustStapleExtension":
            certificate_info.update(
                {COL_OCSP_MUST_STAPLE: False if certificate.get("finding", None) == '--' else True})
        elif id_ == "DNS_CAArecord":
            certificate_info.update(
                {COL_DNS_CAA: False if certificate.get("finding", None) == '--' else True})
        elif id_ == "certificate_transparency":
            certificate_info.update(
                {COL_CERTIFICATE_TRANSPARENCY: True if "yes" in certificate.get("finding", "").lower() else False})

    valid = derive_valid_certificate(certificates_infos)
    at_risk = valid and derive_cert_at_risk(certificates_infos)
    certificate_info.update({COL_VALID_CERTIFICATE: valid, COL_CERT_AT_RISK: at_risk})
    return certificate_info


def extract_protocols(protocols):
    protocols_result = {}
    for protocol in protocols:
        protocol_name = protocol.get("id", None)
        if protocol_name:
            protocols_result.update({protocol_name: False if "not" in protocol.get("finding", "").lower() else True})
    return protocols_result


def extract_rating(ratings):
    rating_result = {}
    for rating in ratings:
        if rating.get("id", None) == "final_score":
            rating_result.update({COL_FINAL_SCORE: rating.get("finding", None)})
        elif rating.get("id", None) == "overall_grade":
            rating_result.update({COL_GRADE: rating.get("finding", None)})
    return rating_result


def save(data, country_code, error=False):
    folder = 'errors' if error else 'results'
    output_dir = os.path.join('.', 'src', 'data', folder)

    os.makedirs(output_dir, exist_ok=True)

    filename = f"{country_code}_https_scanner{'_errors_' if error else ''}.csv"
    output_file = os.path.join(output_dir, filename)

    df = pd.DataFrame(data) if isinstance(data, list) else data

    if not df.empty:
        if os.path.exists(output_file):
            # Resumed runs build their own DataFrame from just that session's
            # rows, so its column order reflects whichever optional keys
            # (e.g. protocols only present for some hosts) appeared first in
            # THIS batch. That order is not guaranteed to match the existing
            # file's header. Appending with header=False writes by position,
            # so any mismatch silently shifts every value into the wrong
            # column for the whole batch. Reindexing to the file's actual
            # header before writing keeps every append aligned by name.
            existing_cols = pd.read_csv(output_file, nrows=0).columns.tolist()
            df = df.reindex(columns=existing_cols)
            df.to_csv(output_file, mode='a', header=False, index=False)
        else:
            df.to_csv(output_file, index=False)
    return output_file
