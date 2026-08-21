import pandas as pd

from src.analyzer.utils.generate_bar_charts import generate_bar_charts
from src.analyzer.utils.generate_tables import generate_tables
from src.config.paths import CONSOLIDATED_RESULT_TO_ANALYZE


def generate_dnssec_status_report(consolidated_dataframe: pd.DataFrame = None):
    if consolidated_dataframe is None:
        consolidated_dataframe = pd.read_csv(CONSOLIDATED_RESULT_TO_ANALYZE)

    generate_tables(consolidated_dataframe, "dnssec_status", "DNSSEC Adoption", ["Valid"])

    # Colours are no longer passed in: chart_style.series_colours maps them by
    # series name, so "Valid" is the same green and "Missing" the same grey in
    # every figure, and a fourth status can appear without silently reusing a
    # colour (the old three-colour list made Missing and Invalid identical).
    generate_bar_charts(consolidated_dataframe, "dnssec_status", "DNSSEC Adoption",
                        None,
                        columns_to_sort=["Valid"], ascending=True)


if __name__ == "__main__":
    generate_dnssec_status_report()
