import os
import pandas as pd

from src.config.config import Config
from src.scanner.models.csv_data_info import CsvDataInfo


def load_csv_data(file_path: str) -> CsvDataInfo:
    df = pd.read_csv(file_path)
    filename: str = os.path.basename(file_path)
    country_code: str = filename[:2]
    url_column: str | None = next((col for col in df.columns if col.lower() == 'url'), None)

    if url_column is None:
        raise ValueError(f"No 'url' column found in CSV ({filename}).")

    if Config.get_error_column() in df.columns:
        df = df.drop(columns=[Config.get_error_column()])

    return CsvDataInfo(df, filename, country_code, url_column)
