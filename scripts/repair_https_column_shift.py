#!/usr/bin/env python3
"""
Repairs the HTTPS scanner column-shift bug (see http_scanner/src/scanner/http.py
save(), fixed to reindex-before-append). Resumed scan sessions produced batches
whose column order didn't match the existing results file's header, and the old
mode='a', header=False append wrote those batches' values into the wrong columns
for the whole session — silently shifting everything from 'ALPN' through
'ALPN_HTTP2' one slot to the right, and losing the row's true ALPN_HTTP2 value
off the end.

This is 100% recoverable without re-scanning: the full raw testssl.sh JSON for
each affected row is still present in the CSV (parked in whichever column the
shift happened to land it in), and re-running it through the scanner's own
extract_result() reproduces the original, correctly-mapped values.

Usage:
    python scripts/repair_https_column_shift.py <file1.csv> [file2.csv ...]

Only rewrites rows detected as shifted (non-numeric final_score with other scan
data present). Rows with no scan data at all (never reachable) are left as-is.
Rows where no recoverable JSON blob can be found are left as-is and reported.
"""
import csv
import json
import sys
from pathlib import Path

SCANNER_ROOT = Path(__file__).resolve().parents[1] / "http_scanner"
sys.path.insert(0, str(SCANNER_ROOT))
from src.scanner.http import extract_result  # noqa: E402

# Columns confirmed (by diffing a shifted row's recompute against its raw CSV
# values) to fall inside the shifted block for every affected row.
SHIFTED_ZONE = [
    "ALPN",
    "certificate_signature_algorithm", "key_size", "ocsp_stapling",
    "ocsp_must_staple", "dns_caa", "certificate_transparency",
    "certificate_authority", "valid_certificate", "cert_at_risk",
    "http_status_code", "banner_server", "banner_application",
    "final_score", "grade", "raw_result_http", "ALPN_HTTP2",
]


def _try_parse_scan_json(value):
    if not value or not value.strip().startswith("{"):
        return None
    try:
        obj = json.loads(value)
    except Exception:
        return None
    return obj if isinstance(obj, dict) and "scanResult" in obj else None


def is_shifted(row):
    fs = row.get("final_score", "")
    try:
        float(fs)
        return False
    except (TypeError, ValueError):
        pass
    # Genuinely never scanned (host unreachable) — nothing to repair.
    if not row.get("http_status_code", "") and not row.get("banner_server", ""):
        return False
    return True


def find_recovered_json(row):
    # Shift width isn't always exactly one column — a row missing an extra
    # optional key (e.g. no "ALPN" entry at all) drifts further right. Search
    # every field rather than assuming a fixed offset; extract_result()
    # re-derives every value from the JSON by name, so locating it is the
    # only thing that depends on shift width.
    for value in row.values():
        blob = _try_parse_scan_json(value)
        if blob is not None:
            return blob
    return None


def repair_row(row):
    raw_json = find_recovered_json(row)
    if raw_json is None:
        return None, "no-recoverable-json"
    try:
        recomputed = extract_result(raw_json)
    except Exception as e:
        return None, f"extract_result-failed: {e}"
    fixed = dict(row)
    for col in SHIFTED_ZONE:
        fixed[col] = recomputed.get(col, "")
    return fixed, "ok"


def repair_file(path):
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    n_clean = n_fixed = n_unresolved = 0
    unresolved_ids = []
    for i, row in enumerate(rows):
        if not is_shifted(row):
            n_clean += 1
            continue
        fixed, status = repair_row(row)
        if fixed is None:
            n_unresolved += 1
            unresolved_ids.append(row.get("Id") or row.get("ID") or row.get("ETER_ID") or "?")
            continue
        rows[i] = fixed
        n_fixed += 1

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    return {
        "path": str(path),
        "total": len(rows),
        "clean": n_clean,
        "fixed": n_fixed,
        "unresolved": n_unresolved,
        "unresolved_ids": unresolved_ids,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for arg in sys.argv[1:]:
        result = repair_file(arg)
        print(f"{result['path']}: total={result['total']} clean={result['clean']} "
              f"fixed={result['fixed']} unresolved={result['unresolved']}")
        if result["unresolved_ids"]:
            print(f"  unresolved IDs: {result['unresolved_ids']}")
