import textwrap

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

from src.analyzer.utils.color_format_chart_bar import format_bar_annotations
from src.analyzer.utils.dataframe_stats import get_dataframe_stats
from src.analyzer.utils.generate_bar_charts import generate_bar_charts
from src.analyzer.utils.generate_tables import generate_tables
from src.analyzer.utils.wrap_labels import wrap_labels
from src.config.paths import CONSOLIDATED_RESULT_TO_ANALYZE


def generate_non_existence_proof_report(consolidated_dataframe: pd.DataFrame | None = None):
    if consolidated_dataframe is None:
        consolidated_dataframe = pd.read_csv(CONSOLIDATED_RESULT_TO_ANALYZE)

    consolidated_dataframe = consolidated_dataframe[consolidated_dataframe['dnssec_status'] == 'Valid']

    generate_tables(consolidated_dataframe, "non_existence_proof_method", "Non-Existence Proof Method",
                    ["NSEC", "NSEC3"])

    generate_bar_charts(consolidated_dataframe, "non_existence_proof_method", "Non-Existence Proof Method",
                        None,   # colours resolved by series name in chart_style
                        columns_to_sort=["NSEC", "NSEC3"], ascending=True)


if __name__ == "__main__":
    generate_non_existence_proof_report()
