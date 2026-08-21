import logging
import re

from src.config import config, EXPECTED_HEADERS_KEY, DEPRECATED_HEADERS, HEADERS_MULTIPLIERS, CRITICAL_HEADERS, \
    COL_CRITICAL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS, \
    COL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS

total_valid_headers = len(config[EXPECTED_HEADERS_KEY]) - len(config[DEPRECATED_HEADERS])
HEADER_PRESENCE = 100 / total_valid_headers
STRONG_CONFIGURATION = 1.4
WEAK_CONFIGURATION = 0.85
HTTP_V2_POINTS = 1.1
HTTP_V3_POINTS = 1.3
PENALTY_DEPRECATED_HEADER = 0.6
PENALTY_BETWEEN_PLATFORMS_CRITICAL = 0.85
PENALTY_BETWEEN_PLATFORMS_NON_CRITICAL = 0.90
HEADER_SCORE_BY_PLATFORM_COL = "header_score_by_platform"
HEADER_AVG_SCORE_BTW_PLATFORMS_COL = "header_avg_score_btw_platforms"
HEADER_COMPONENT_SCORE_COL = "header_component_score"

# Columns that can be used as a fallback for ETER_ID
_URL_CANDIDATE_COLS = ["url", "URL", "Url", "domain", "Domain", "website", "Website"]


def _ensure_eter_id(dataframe):
    """
    Ensures the DataFrame has an ETER_ID column.

    Priority:
      1. Column already exists -> use as-is.
      2. 'ID' column exists -> copy it to ETER_ID.
      3. 'Id' column exists (Polish dataset) -> cast to str and copy.
      4. A URL/domain column exists -> extract the hostname as a synthetic ID.
      5. No usable column -> use the row index (cross-platform comparison disabled).
    """
    if "ETER_ID" in dataframe.columns:
        return dataframe

    # Fallback to 'ID' column (used by the Norwegian dataset).
    if "ID" in dataframe.columns:
        dataframe = dataframe.copy()
        dataframe["ETER_ID"] = dataframe["ID"]
        logging.debug("Created 'ETER_ID' from 'ID' column.")
        return dataframe

    # Fallback to 'Id' column (used by the Polish dataset).
    if "Id" in dataframe.columns:
        dataframe = dataframe.copy()
        dataframe["ETER_ID"] = dataframe["Id"].astype(str)
        logging.debug("Created 'ETER_ID' from 'Id' column.")
        return dataframe

    for col in _URL_CANDIDATE_COLS:
        if col in dataframe.columns:
            dataframe = dataframe.copy()
            dataframe["ETER_ID"] = dataframe[col].apply(
                lambda x: re.sub(r"^https?://(www\.)?", "", str(x)).split("/")[0].lower()
            )
            logging.debug(
                "Created synthetic 'ETER_ID' from column '%s' (hostname extracted).",
                col,
            )
            return dataframe

    # Last resort: no URL column either
    dataframe = dataframe.copy()
    dataframe["ETER_ID"] = dataframe.index.astype(str)
    logging.debug(
        "No suitable column for ETER_ID. Using row index. "
        "Available columns: %s",
        dataframe.columns.tolist(),
    )
    return dataframe


def calculate_header_scores(dataframe):
    dataframe = _ensure_eter_id(dataframe)

    expected_headers = list({k.lower(): v for k, v in config[EXPECTED_HEADERS_KEY].items()}.keys())
    platform_counts = dataframe["platform"].nunique()
    dataframe[HEADER_SCORE_BY_PLATFORM_COL] = 0
    dataframe[HEADER_AVG_SCORE_BTW_PLATFORMS_COL] = 0
    dataframe[HEADER_COMPONENT_SCORE_COL] = 0

    dataframe[HEADER_SCORE_BY_PLATFORM_COL] = dataframe.apply(
        lambda x: sum(calculate_header_presence_and_config(header, x) for header in expected_headers),
        axis=1
    ).round(2)

    dataframe[HEADER_AVG_SCORE_BTW_PLATFORMS_COL] = dataframe.groupby(
        ["ETER_ID"]
    )[HEADER_SCORE_BY_PLATFORM_COL].transform("mean").round(2)

    check_inconsistencies(dataframe)

    penalty_combined = (
            dataframe[COL_CRITICAL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS]
            * PENALTY_BETWEEN_PLATFORMS_CRITICAL
            * (1 - (platform_counts / 100))
            +
            dataframe[COL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS]
            * PENALTY_BETWEEN_PLATFORMS_NON_CRITICAL
            * (1 - (platform_counts / 100))
    )
    penalty_combined = penalty_combined.where(penalty_combined > 0, 1)
    http_version_multiplier = dataframe["protocol_http"].apply(
        lambda x: HTTP_V3_POINTS if x.lower() == "h3" else HTTP_V2_POINTS if x.lower() == "h2" else 1
    )

    dataframe[HEADER_COMPONENT_SCORE_COL] = (
            (dataframe[HEADER_AVG_SCORE_BTW_PLATFORMS_COL]
            * http_version_multiplier)
            * penalty_combined
    ).clip(upper=100).round(2)

    return dataframe


def calculate_header_presence_and_config(header, row):
    deprecated_headers = [h.lower() for h in config[DEPRECATED_HEADERS]]
    multipliers = {k.lower(): v for k, v in config[HEADERS_MULTIPLIERS].items()}
    presence_col = f"{header}_presence"
    config_col = f"{header}_config"
    header_score = 0

    if row.get(presence_col, False):
        header_score += HEADER_PRESENCE

        if header in deprecated_headers:
            header_score *= PENALTY_DEPRECATED_HEADER

        config_value = row.get(config_col, "Missing")
        if config_value.lower() == "strong":
            header_score *= STRONG_CONFIGURATION
        elif config_value.lower() == "weak":
            header_score *= WEAK_CONFIGURATION

        header_score *= multipliers.get(header, 1)

    return round(min(header_score, 100), 2)


def check_inconsistencies(dataframe):
    expected_headers = list({k.lower(): v for k, v in config[EXPECTED_HEADERS_KEY].items()}.keys())
    critical_headers = [header.lower() for header in config[CRITICAL_HEADERS]]
    inconsistencies_columns = [
        COL_CRITICAL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS,
        COL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS
    ]
    for col in inconsistencies_columns:
        headers_to_check = critical_headers if "critical" in col.lower() else expected_headers

        group_by = dataframe.groupby(["ETER_ID"])[
                       [f"{header}_presence" for header in headers_to_check] +
                       [f"{header}_config" for header in headers_to_check]
                       ].nunique() > 1

        dataframe[col] = dataframe["ETER_ID"].map(group_by.any(axis=1))
