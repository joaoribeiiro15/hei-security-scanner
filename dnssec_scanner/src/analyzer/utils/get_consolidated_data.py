import logging
import os
import re
import pandas as pd

from src.config.config import Config
from src.config.paths import DATA_RESULTS_DIRECTORY, CONSOLIDATED_RESULT_TO_ANALYZE

# Column name aliases that may appear in result CSV files produced by different
# scanner runs or for different countries.  Each entry maps a legacy/variant
# column name to the canonical name used throughout the analysis pipeline.
_COLUMN_ALIASES: dict[str, str] = {
    # Some result files (e.g. DE/FR/IT backups) use "ETER_ID" while newer
    # files (e.g. NO) use "ID".  Normalise to "ID" so that
    # Config.get_id_column() always resolves correctly.
    "ETER_ID": "ID",
    # Polish dataset uses "Id" (mixed case) instead of "ID".
    "Id": "ID",
}


def _normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename any variant column names to their canonical equivalents.

    This allows the rest of the pipeline to work with a single, consistent
    set of column names regardless of which country's result file is loaded.
    """
    rename = {src: dst for src, dst in _COLUMN_ALIASES.items() if src in df.columns}
    if rename:
        logging.debug(f"Normalising columns: {rename}")
        df = df.rename(columns=rename)

    # Resolve NUTS2_Label from variant column names.  Prefer the 2021
    # vintage over 2016; fall back to the raw NUTS2 code or Region column
    # (used by datasets without NUTS2 classification, e.g. Poland).
    if "NUTS2_Label" not in df.columns:
        if "NUTS2_Label_2021" in df.columns:
            df = df.rename(columns={"NUTS2_Label_2021": "NUTS2_Label"})
        elif "NUTS2_Label_2016" in df.columns:
            df = df.rename(columns={"NUTS2_Label_2016": "NUTS2_Label"})
        elif "NUTS2" in df.columns:
            df = df.copy()
            df["NUTS2_Label"] = df["NUTS2"]
        elif "Region" in df.columns:
            df = df.copy()
            df["NUTS2_Label"] = df["Region"]
        else:
            df = df.copy()
            df["NUTS2_Label"] = "N/A"

    return df


def generate_consolidated_data() -> pd.DataFrame:
    files: list[str] = [f for f in os.listdir(DATA_RESULTS_DIRECTORY) if re.match(r'^[a-zA-Z]{2}_.*\.csv$', f)]

    if not files:
        logging.warning(
            f"No CSV files found in '{DATA_RESULTS_DIRECTORY}'. Please ensure the files are in the correct directory."
            f"\n The expected format is 'country_platform.csv', where country is the ISO 3166-1 alpha-2 code and platform is the platform name."
        )
        return

    logging.info(f"Found {len(files)} files to consolidate.")

    dataframes: list[pd.DataFrame] = []
    for file in files:
        file_path: str = os.path.join(DATA_RESULTS_DIRECTORY, file)
        try:
            country_code: str = os.path.basename(file_path)[:2]
            logging.info(f"Loading file: {file} (Country: {country_code})")

            df: pd.DataFrame = pd.read_csv(file_path)

            # Normalise column names before any other operation so that both
            # legacy and current result files are handled uniformly.
            df = _normalise_columns(df)

            df[Config.get_country_column()] = country_code
            # Keep only the row with the lowest score per institution to avoid
            # counting the same domain more than once when a file has duplicates.
            # groupby(...).idxmin() raises "'[nan] not in index'" whenever an
            # institution's every row has a missing score — idxmin() of an
            # all-NaN group returns NaN, which .loc[] then can't resolve.
            # Sort with valid scores first instead: institutions with at
            # least one usable score keep their lowest one, institutions
            # with none still keep one row instead of being silently dropped.
            id_col = Config.get_id_column()
            score_col = Config.get_score_column()
            df["_valid"] = df[score_col].notna().astype(int)
            df = df.sort_values(["_valid", score_col], ascending=[False, True])
            df = df.drop_duplicates(subset=id_col, keep="first")
            df = df.drop(columns=["_valid"])
            dataframes.append(df)

        except Exception as e:
            logging.error(f"Failed to load '{file}': {e}")

    try:
        consolidated_dataframe: pd.DataFrame = pd.concat(dataframes, ignore_index=True)

        # Normalize Category to lowercase so that downstream filters
        # ("public", "private") match regardless of the source casing.
        if "Category" in consolidated_dataframe.columns:
            consolidated_dataframe["Category"] = consolidated_dataframe["Category"].str.lower()

        consolidated_dataframe.to_csv(CONSOLIDATED_RESULT_TO_ANALYZE, index=False, encoding='utf-8')
        logging.info(f"Consolidated data saved to: {CONSOLIDATED_RESULT_TO_ANALYZE}")
        return consolidated_dataframe
    except Exception as e:
        logging.error(f"Failed to build consolidated dataframe: {e}")
        raise e
