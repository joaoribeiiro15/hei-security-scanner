from src.analyzer.setup import DATA_SOURCE_DIRECTORY, FILE_TO_ANALYZE
import json
import logging
import os
import re
import pandas as pd

from src.scanner.cert_validation import derive_valid_certificate, derive_cert_at_risk


# Columns stored as "True"/"False" strings in the CSV that must be converted
# to actual Python booleans before any groupby / unstack operations.
BOOL_COLUMNS = [
    "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
    "NPN", "ALPN_HTTP2", "ALPN",
    "valid_certificate", "cert_at_risk", "ocsp_stapling", "ocsp_must_staple",
    "dns_caa", "certificate_transparency",
]

_BOOL_MAP = {"True": True, "False": False, True: True, False: False}


def extract_country(filename):
    parts = filename.replace('.csv', '').split('_')
    if len(parts) < 2:
        raise ValueError(
            f"Invalid filename format: {filename}. Expected format: 'country_platform.csv'"
        )
    return parts[0]


def consolidate_data():
    files = [f for f in os.listdir(DATA_SOURCE_DIRECTORY) if re.match(r'^[a-zA-Z]{2}_.*\.csv$', f)]
    print(f"Found {len(files)} result files to analyze.")

    if not files:
        print(
            f"No CSV files found in '{DATA_SOURCE_DIRECTORY}'. "
            f"Please ensure the files are in the correct directory."
        )
        return []

    data_frames = []
    for file in files:
        file_path = os.path.join(DATA_SOURCE_DIRECTORY, file)
        try:
            country = extract_country(os.path.basename(file))
            print(f"Loading file: {file} (Country: {country})")

            df = pd.read_csv(file_path)

            # Convert boolean columns from "True"/"False" strings to real booleans.
            # A non-empty string is truthy in Python, which would cause every
            # protocol check (e.g. if row["SSLv2"]:) to evaluate as True even
            # when the value is the string "False".
            for col in BOOL_COLUMNS:
                if col in df.columns:
                    df[col] = df[col].map(_BOOL_MAP)

            # The NO scanner writes the URL column as "url" (lowercase).
            # Normalise to "Url" to match config.desired_column_order.
            if "url" in df.columns and "Url" not in df.columns:
                df.rename(columns={"url": "Url"}, inplace=True)

            # Normalise ID column: "ID" (NO) or "ETER_ID" (DE/FR/IT) or "Id" (PL).
            if "ETER_ID" not in df.columns and "ID" in df.columns:
                df["ETER_ID"] = df["ID"]
            elif "ETER_ID" not in df.columns and "Id" in df.columns:
                df["ETER_ID"] = df["Id"]

            # Normalise NUTS2_Label: prefer 2021 vintage, fall back to 2016,
            # then raw NUTS2 code, then Region (Poland), then "N/A".
            if "NUTS2_Label" not in df.columns:
                if "NUTS2_Label_2021" in df.columns:
                    df.rename(columns={"NUTS2_Label_2021": "NUTS2_Label"}, inplace=True)
                elif "NUTS2_Label_2016" in df.columns:
                    df.rename(columns={"NUTS2_Label_2016": "NUTS2_Label"}, inplace=True)
                elif "NUTS2" in df.columns:
                    df["NUTS2_Label"] = df["NUTS2"]
                elif "Region" in df.columns:
                    df["NUTS2_Label"] = df["Region"]
                else:
                    df["NUTS2_Label"] = "N/A"

            df['country'] = country

            # Keep only the row with the lowest final_score per institution.
            # groupby(...).idxmin() raises "'[nan] not in index'" whenever an
            # institution's every row has a missing final_score (e.g. cert
            # data unavailable on every run) — idxmin() of an all-NaN group
            # returns NaN, which .loc[] then can't resolve. Sort with valid
            # scores first instead: institutions with at least one usable
            # score keep their lowest one, institutions with none still keep
            # one row (so they aren't silently dropped from the dataset).
            df["_valid"] = df["final_score"].notna().astype(int)
            df = df.sort_values(["_valid", "final_score"], ascending=[False, True])
            df = df.drop_duplicates(subset="ETER_ID", keep="first")
            df = df.drop(columns=["_valid"])

            data_frames.append(df)
        except Exception as e:
            print(f"Error loading {file}: {e}")

    consolidate_df = pd.concat(data_frames, ignore_index=True) if data_frames else pd.DataFrame()

    # Normalise Category to lowercase so downstream filters
    # ("public", "private") match regardless of source casing.
    if "Category" in consolidate_df.columns:
        consolidate_df["Category"] = consolidate_df["Category"].str.lower()

    consolidate_df.to_csv(FILE_TO_ANALYZE, index=False)
    print(f"Consolidated data saved in: {FILE_TO_ANALYZE}")
    return consolidate_df


def get_country(country_code):
    mapping = {
        "no": "Norway", "de": "Germany", "pl": "Poland", "fr": "France",
        "it": "Italy", "pt": "Portugal", "es": "Spain", "se": "Sweden",
        "dk": "Denmark", "fi": "Finland", "nl": "Netherlands", "be": "Belgium",
        "at": "Austria", "ch": "Switzerland", "cz": "Czech Republic",
        "hu": "Hungary", "ro": "Romania", "gr": "Greece",
    }
    return mapping.get(country_code.lower() if isinstance(country_code, str) else country_code, country_code)


def get_reverse_country(country_name):
    mapping = {
        "Norway": "no", "Germany": "de", "Poland": "pl", "France": "fr",
        "Italy": "it", "Portugal": "pt", "Spain": "es", "Sweden": "se",
        "Denmark": "dk", "Finland": "fi", "Netherlands": "nl", "Belgium": "be",
        "Austria": "at", "Switzerland": "ch", "Czech Republic": "cz",
        "Hungary": "hu", "Romania": "ro", "Greece": "gr",
    }
    return mapping.get(country_name, country_name)


def _server_defaults_for_worst(raw_json):
    """Return the serverDefaults list for the scan result with the lowest final_score."""
    scan_results = raw_json.get("scanResult", [])
    if not isinstance(scan_results, list):
        scan_results = [scan_results]

    best_score = None
    best_sd = []
    for sr in scan_results:
        score = None
        for r in sr.get("rating", []):
            if r.get("id") == "final_score":
                try:
                    score = float(r.get("finding", float("inf")))
                except (ValueError, TypeError):
                    score = float("inf")
                break
        if score is None:
            score = float("inf")
        if best_score is None or score < best_score:
            best_score = score
            best_sd = sr.get("serverDefaults", [])
    return best_sd


def rederive_csv(csv_path):
    """
    Re-compute valid_certificate and cert_at_risk from raw_result_http for
    every row in csv_path, then write the updated DataFrame back to the same
    file.  Adds the cert_at_risk column if it is absent.
    """
    df = pd.read_csv(csv_path)
    if "raw_result_http" not in df.columns:
        logging.warning("rederive_csv: no raw_result_http column in %s, skipping", csv_path)
        return

    valid_values = []
    at_risk_values = []
    for _, row in df.iterrows():
        try:
            raw_json = json.loads(row["raw_result_http"])
            sd = _server_defaults_for_worst(raw_json)
            valid = derive_valid_certificate(sd)
            at_risk = valid and derive_cert_at_risk(sd)
        except Exception as exc:
            logging.warning("rederive_csv: failed to process row %s: %s", row.get("Name", "?"), exc)
            valid = False
            at_risk = False
        valid_values.append(valid)
        at_risk_values.append(at_risk)

    df["valid_certificate"] = valid_values
    df["cert_at_risk"] = at_risk_values

    # Per-institution promotion: a run where cert data was unavailable
    # (connection failure, no serverDefaults) should not override a run
    # where the cert was verified as valid.  If any run for an institution
    # has valid_certificate=True, treat all runs as valid so that
    # consolidate_data (which picks idxmin by final_score) inherits the
    # correct certificate status even for partial-data runs.
    id_col = next((c for c in ("ETER_ID", "ID") if c in df.columns), None)
    if id_col:
        best_valid = df.groupby(id_col)["valid_certificate"].transform("max")
        # Promote at_risk only for institutions that are actually valid
        best_at_risk = df.groupby(id_col)["cert_at_risk"].transform("max")
        df["valid_certificate"] = best_valid
        df["cert_at_risk"] = best_at_risk & df["valid_certificate"]

    # Ensure cert_at_risk sits immediately after valid_certificate
    if "valid_certificate" in df.columns and "cert_at_risk" in df.columns:
        cols = [c for c in df.columns if c != "cert_at_risk"]
        vc_idx = cols.index("valid_certificate")
        cols.insert(vc_idx + 1, "cert_at_risk")
        df = df[cols]

    df.to_csv(csv_path, index=False)
    logging.info("rederive_csv: updated %s (%d rows)", csv_path, len(df))
