import logging
import os
import time

import pandas as pd
import requests

from src.scanner.browser import get_scan_result
from src.config import config
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from src.scanner.utils.utils import save, sanitize_url, normalize_domain

lock = threading.Lock()

results_by_platform = {list(device.keys())[0]: [] for device in config['user_agents']}
errors = []
HTTP = "http://"
HTTPS = "https://"

MAX_RETRIES = 2
RETRY_DELAY = 2  # seconds


def run_scan(input_file):
    global results_by_platform, errors
    errors = []
    results_by_platform = {list(device.keys())[0]: [] for device in config['user_agents']}

    filename = os.path.basename(input_file)
    country_code = filename[:2]
    language = next((lang[country_code] for lang in config['languages'] if country_code in lang), 'en')
    max_threads = config.get('max_threads', 5)

    df = pd.read_csv(input_file)
    if "error" in df.columns:
        df = df.drop(columns=["error"])

    url_column_name = next((col for col in df.columns if col.lower() == 'url'), None)
    if url_column_name is None:
        raise ValueError(f"No 'url' column found in CSV ({filename}).")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(row_scan, row, url_column_name, language) for _, row in df.iterrows()]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Thread error in CSV ({filename}): {e}")

    for platform, results in results_by_platform.items():
        save(results, country_code, platform)
    if errors:
        save(errors, country_code, '', error=True)


def _is_connect_failure(exc):
    """True if the error is a TCP connect timeout or refusal — no point retrying."""
    msg = str(exc).lower()
    return "connecttimeouterror" in msg or "connection refused" in msg or "connect timeout" in msg


def _try_get(url, user_agent, language):
    """Attempt a request, retrying only on transient errors (not connect failures)."""
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return get_scan_result(url, user_agent, language)
        except Exception as e:
            last_exc = e
            if _is_connect_failure(e):
                # No point retrying a closed port
                raise
            logging.warning(f"Attempt {attempt}/{MAX_RETRIES} failed for {url}: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    raise last_exc


def row_scan(row, url_column_name, language):
    process_result_by_platform = {}
    process_error = []
    base_url = sanitize_url(row[url_column_name])
    http_url = f"{HTTP}{base_url}"
    https_url = f"{HTTPS}{base_url}"

    for device in config['user_agents']:
        platform = list(device.keys())[0]
        user_agent = list(device.values())[0]

        result = {
            "assessment_datetime": None,
            "http_status_code": None,
            "https_status_code": None,
            "redirected_to_https": False,
            "redirected_https_to_same_domain": False,
            "final_url": None,
            "idioma": language,
            "platform": platform,
            "protocol_http": None,
            "redirect_count": None,
        }

        try:
            http_scan = None
            try:
                logging.info(f"Scanning HTTP: {base_url} - {platform}")
                http_scan = _try_get(http_url, user_agent, language)
                result["http_status_code"] = http_scan.initial_status
                result["redirected_to_https"] = http_scan.final_url.startswith(HTTPS)
            except Exception as e:
                logging.warning(f"HTTP unreachable for {base_url} ({platform}), trying HTTPS directly: {e}")

            if result["redirected_to_https"] and http_scan:
                result["https_status_code"] = http_scan.final_status
                base_domain = normalize_domain(base_url)
                final_domain = normalize_domain(http_scan.final_url)
                result["redirected_https_to_same_domain"] = base_domain == final_domain
                scan_result = http_scan
            else:
                logging.info(f"Scanning HTTPS: {base_url} - {platform}")
                scan_result = _try_get(https_url, user_agent, language)
                result["https_status_code"] = scan_result.final_status
                if http_scan is None:
                    result["redirected_to_https"] = scan_result.final_url.startswith(HTTPS)

            result.update({
                "protocol_http": scan_result.protocol,
                "final_url": scan_result.final_url,
                "redirect_count": scan_result.redirect_count,
                "assessment_datetime": pd.Timestamp.now(),
                **assessing_security_headers(scan_result.headers)
            })
            process_result_by_platform[platform] = {**row.to_dict(), **result}

        except Exception as e:
            logging.error(f"Error scanning {base_url} - {platform}: {e}")
            process_error.append({**row.to_dict(), "error": str(e)})
            break

    with lock:
        for platform, result in process_result_by_platform.items():
            results_by_platform[platform].append(result)
        if process_error:
            errors.extend(process_error)


def assessing_security_headers(received_headers):
    analysis = {}
    normalized_received = {k.lower(): v for k, v in received_headers.items()}
    normalized_expected = {k.lower(): v for k, v in config['expected_headers'].items()}

    for expected_header, heuristic in normalized_expected.items():
        received_value = normalized_received.get(expected_header, "Missing")
        analysis[f"{expected_header}_presence"] = received_value != "Missing"
        analysis[f"{expected_header}_config"] = heuristic(received_value) if received_value != "Missing" else "Missing"

    analysis['raw_headers'] = str(received_headers)
    return analysis
