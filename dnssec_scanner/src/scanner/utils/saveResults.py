import os.path

import pandas as pd

from src.config.paths import DATA_BASE_DIRECTORY, DATA_RESULTS_DIRECTORY, DATA_ERRORS_DIRECTORY

# Tracks which output files have been written in the current process run.
# First write → overwrite (prevents accumulation from prior runs).
# Subsequent writes within the same run → append (accumulates results when
# multiple source CSVs map to the same country output file).
_written_this_run: set[str] = set()


def save_results(data: list[dict[str, any]], country_code: str, error: bool = False):
    folder: str = DATA_ERRORS_DIRECTORY if error else DATA_RESULTS_DIRECTORY
    output_directory: str = os.path.join(DATA_BASE_DIRECTORY, folder)

    os.makedirs(output_directory, exist_ok=True)

    filename: str = os.path.join(output_directory,
                                 f"{country_code.strip()}_dnssec_scanner{'_errors_' if error else ''}.csv")

    df: pd.DataFrame = pd.DataFrame(data)

    if not df.empty:
        first_write = filename not in _written_this_run
        _written_this_run.add(filename)
        if first_write:
            df.to_csv(filename, index=False, encoding='utf-8')
        else:
            df.to_csv(filename, mode='a', header=False, index=False, encoding='utf-8')
