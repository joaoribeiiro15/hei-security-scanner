import logging
import pandas as pd

from src.analyzer.dnssec_status_report import generate_dnssec_status_report
from src.analyzer.non_existence_proof_report import generate_non_existence_proof_report
from src.analyzer.score_report import generate_score_report
from src.analyzer.utils.get_consolidated_data import generate_consolidated_data
from src.utils.logging_setup import logging_setup


def generate_reports():
    consolidated_dataframe: pd.DataFrame = generate_consolidated_data()
    generate_dnssec_status_report(consolidated_dataframe)
    generate_non_existence_proof_report(consolidated_dataframe)
    generate_score_report(consolidated_dataframe)


if __name__ == "__main__":
    try:
        logging_setup()
        generate_reports()
    except Exception as e:
        logging.error(e)
