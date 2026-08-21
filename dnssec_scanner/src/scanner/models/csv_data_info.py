from dataclasses import dataclass
import pandas as pd


@dataclass
class CsvDataInfo:
    dataframe: pd.DataFrame
    filename: str
    country_code: str
    url_column: str
