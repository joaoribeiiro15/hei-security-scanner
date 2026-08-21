import logging
import re


def get_country(country):
    mapping = {
        "de": "Germany", "fr": "France", "it": "Italy", "no": "Norway",
        "pl": "Poland", "pt": "Portugal", "es": "Spain", "se": "Sweden",
        "dk": "Denmark", "fi": "Finland", "nl": "Netherlands", "be": "Belgium",
        "at": "Austria", "ch": "Switzerland", "cz": "Czech Republic",
        "hu": "Hungary", "ro": "Romania", "gr": "Greece",
    }
    return mapping.get(country.lower() if isinstance(country, str) else country, country)


def get_reverse_country(country):
    mapping = {
        "Germany": "de", "France": "fr", "Italy": "it", "Norway": "no",
        "Poland": "pl", "Portugal": "pt", "Spain": "es", "Sweden": "se",
        "Denmark": "dk", "Finland": "fi", "Netherlands": "nl", "Belgium": "be",
        "Austria": "at", "Switzerland": "ch", "Czech Republic": "cz",
        "Hungary": "hu", "Romania": "ro", "Greece": "gr",
    }
    return mapping.get(country, country)


_URL_CANDIDATE_COLS = ["url", "URL", "Url", "domain", "Domain", "website", "Website"]


def _ensure_country(dataframe):
    """
    Ensures a 'country' column exists.
    Derives it from 'ID'/'ETER_ID' prefix (e.g. 'DE0001' -> 'DE'),
    then from 'NUTS2' code prefix (e.g. 'DE13' -> 'DE').
    Falls back to 'N/A' when no reliable column is available.
    """
    if "country" in dataframe.columns:
        return dataframe

    dataframe = dataframe.copy()
    for col in ("ID", "ETER_ID"):
        if col in dataframe.columns:
            sample = str(dataframe[col].iloc[0]) if not dataframe.empty else ""
            if len(sample) >= 2 and sample[:2].isalpha():
                dataframe["country"] = dataframe[col].astype(str).str[:2].str.upper()
                logging.debug("Created 'country' from '%s' column (first 2 characters).", col)
                return dataframe

    if "NUTS2" in dataframe.columns:
        dataframe["country"] = dataframe["NUTS2"].astype(str).str[:2].str.upper()
        logging.debug("Created 'country' from 'NUTS2' column (first 2 characters).")
        return dataframe

    dataframe["country"] = "N/A"
    logging.warning(
        "Cannot determine 'country': no usable ID or NUTS2 column. "
        "Available columns: %s", dataframe.columns.tolist()
    )
    return dataframe


def _ensure_nuts2_label(dataframe):
    """
    Ensures a 'NUTS2_Label' column exists and is fully populated.
    Checks variant column names (2021/2016 vintages), then falls back to
    'NUTS2', then 'Region' (used by datasets without NUTS2, e.g. Poland),
    then 'N/A'.
    When the column already exists but contains NaN (common after multi-country
    concat where only some schemas have NUTS2_Label), fills NaN values from
    the same fallback order before returning.
    """
    _FALLBACKS = ["NUTS2_Label_2021", "NUTS2_Label_2016", "NUTS2", "Region"]

    if "NUTS2_Label" in dataframe.columns:
        if dataframe["NUTS2_Label"].isna().any():
            dataframe = dataframe.copy()
            for alt in _FALLBACKS:
                if alt in dataframe.columns:
                    dataframe["NUTS2_Label"] = dataframe["NUTS2_Label"].fillna(dataframe[alt])
            dataframe["NUTS2_Label"] = dataframe["NUTS2_Label"].fillna("N/A")
        return dataframe

    dataframe = dataframe.copy()
    for alt in _FALLBACKS:
        if alt in dataframe.columns:
            dataframe["NUTS2_Label"] = dataframe[alt]
            logging.debug("Created 'NUTS2_Label' from '%s' column.", alt)
            return dataframe

    dataframe["NUTS2_Label"] = "N/A"
    logging.warning("NUTS2_Label missing and no fallback found; using 'N/A'.")
    return dataframe


def _ensure_eter_id(dataframe):
    """
    Ensures an 'ETER_ID' column exists.
    Falls back to 'ID', 'Id', then URL hostname, then row index.
    """
    if "ETER_ID" in dataframe.columns:
        return dataframe

    if "ID" in dataframe.columns:
        dataframe = dataframe.copy()
        dataframe["ETER_ID"] = dataframe["ID"]
        logging.debug("Created 'ETER_ID' from 'ID' column.")
        return dataframe

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
                "Created synthetic 'ETER_ID' from '%s' (hostname extracted).", col
            )
            return dataframe

    dataframe = dataframe.copy()
    dataframe["ETER_ID"] = dataframe.index.astype(str)
    logging.debug(
        "No suitable column for ETER_ID. Using row index. "
        "Available columns: %s", dataframe.columns.tolist()
    )
    return dataframe
