import pandas as pd

from src.analyzer.utils.generate_bar_charts import generate_bar_charts
from src.analyzer.utils.generate_tables import generate_tables
from src.config.paths import CONSOLIDATED_RESULT_TO_ANALYZE


def generate_score_report(consolidated_dataframe: pd.DataFrame | None = None):
    """Generate tables and charts for the DNSSEC Average Score report.

    Reads the consolidated result CSV when no dataframe is supplied directly
    (e.g. when the module is executed as a standalone script).
    """
    if consolidated_dataframe is None:
        consolidated_dataframe = pd.read_csv(CONSOLIDATED_RESULT_TO_ANALYZE)

    # Generate LaTeX tables grouped by country and NUTS2 region.
    generate_tables(
        consolidated_dataframe,
        "score",
        "DNSSEC Average Score",
        columns_to_sort=["Score"],
        avg=True
    )

    # FIX (Bug 4): generate_bar_charts was missing entirely for the score
    # report, so no score charts were ever produced.  Added here to match
    # the pattern used by dnssec_status_report and non_existence_proof_report.
    # FIX (Bug 4): avg=True is required here because 'score' is a continuous
    # numeric column — it must be aggregated as a mean, not treated as a
    # categorical distribution.  Without this flag get_dataframe_stats would
    # try to unstack individual float values as column headers and the
    # subsequent sort_values(["Score"]) would raise a KeyError.
    generate_bar_charts(
        consolidated_dataframe,
        "score",
        "DNSSEC Average Score",
        None,   # colours resolved by series name in chart_style
        columns_to_sort=["Score"],
        ascending=False,
        avg=True
    )


if __name__ == "__main__":
    generate_score_report()
