from src.analyzer.algorithm import make_algorithm_report
from src.analyzer.ca import make_ca_report
from src.analyzer.setup import setup, DATA_SOURCE_DIRECTORY
from src.analyzer.utils import consolidate_data, rederive_csv
from src.analyzer.valid_certificate import make_valid_certificate_report
from src.analyzer.worst_https import make_worst_https_reports
import os
import re


def main(rederive=False):
    setup()
    if rederive:
        files = [f for f in os.listdir(DATA_SOURCE_DIRECTORY) if re.match(r'^[a-zA-Z]{2}_.*\.csv$', f)]
        for f in files:
            rederive_csv(os.path.join(DATA_SOURCE_DIRECTORY, f))
    aggregated_df = consolidate_data()
    make_worst_https_reports(aggregated_df)
    print(aggregated_df.info())
    make_algorithm_report(aggregated_df)
    make_valid_certificate_report(aggregated_df)
    make_ca_report(aggregated_df)


if __name__ == "__main__":
    main()