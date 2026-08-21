import os
from typing import Tuple

# Use the non-interactive 'Agg' backend so that charts can be generated in
# headless environments (servers, CI) where no display is available.
import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import pandas as pd

from src.analyzer.utils.dataframe_stats import get_dataframe_stats
from src.analyzer.utils.get_country_name import get_country_name
from src.analyzer.utils.make_bar_chart import make_bar_chart
from src.analyzer.utils.save_chart import save_chart
from src.config.paths import CHART_DIRECTORY


def generate_bar_charts(consolidated_dataframe: pd.DataFrame, target_column, title_prefix,
                        color_map: list[str],
                        x_label: str = None, y_label: str = None, title: str = None, legend_title: str = None,
                        legend_position: str = None, legend_columns: int = None, bbox_to_anchor: Tuple[int, int] = None,
                        columns_to_sort: list[str] = None, ascending=False, avg: bool = False):
    """Generate stacked horizontal bar charts for a given target column.

    Produces one chart per country broken down by NUTS2 region (overall and
    split by public/private HEI category) plus a single aggregated chart
    across all countries.  Charts are saved as PDF files in CHART_DIRECTORY
    and a LaTeX \\includegraphics input file is written alongside them.

    When avg=True the chart shows the mean value of target_column per group
    (suitable for numeric columns like 'score').  When avg=False (default) it
    shows the percentage distribution of each categorical value.
    """

    columns_to_sort = [] if columns_to_sort is None else columns_to_sort
    legend_title = title_prefix if legend_title is None else legend_title
    countries = consolidated_dataframe["country"].unique()

    # Rename the NUTS2 label column to a shorter display name.
    rename_map = {
        "NUTS2_Label": "NUTS2",
        "score": "Score",
    }

    filenames: list[str] = []

    for country in countries:
        # --- Chart 1: all HEIs in the country grouped by NUTS2 region ---
        group_by = ["country", "NUTS2_Label"]
        stats_df = get_dataframe_stats(consolidated_dataframe, target_column, group_by, rename_map, avg)

        data = stats_df[stats_df["country"] == country].drop(columns=["country"]).sort_values(
            by=columns_to_sort, ascending=ascending
        )
        label: str = f"{title_prefix.replace(' ', '_').lower()}_in_{get_country_name(country).lower()}_by_nuts2"
        x_axis_label = f"{title_prefix} (avg)" if avg else f"{title_prefix} (%)"
        chart = make_bar_chart(
            data, "NUTS2", x_axis_label, "NUTS2",
            f"{title_prefix} in {get_country_name(country)} by NUTS2 ({'avg' if avg else '%'})", legend_title, color_map
        )
        filename: str = f"{label}.pdf"
        chart.savefig(os.path.join(CHART_DIRECTORY, filename), format="pdf", bbox_inches="tight")
        filenames.append(filename)
        plt.close(chart)

        # --- Charts 2 & 3: public and private HEIs separately, by NUTS2 ---
        group_by = ["country", "NUTS2_Label", "Category"]
        stats_df = get_dataframe_stats(consolidated_dataframe, target_column, group_by, rename_map, avg)
        for _, category in enumerate(["public", "private"]):
            data = stats_df[
                (stats_df["country"] == country) & (stats_df["Category"] == category)
            ].drop(columns=["country", "Category"]).sort_values(by=columns_to_sort, ascending=ascending)

            label = (
                f"{title_prefix.replace(' ', '_').lower()}"
                f"_at_{category}_hei_in_{get_country_name(country).lower()}_by_nuts2"
            )
            if not data.empty:
                chart = make_bar_chart(
                    data, "NUTS2", x_axis_label, "NUTS2",
                    f"{title_prefix} at {category.capitalize()} HEIs in {get_country_name(country)} ({'avg' if avg else '%'})",
                    legend_title, color_map
                )
                filename = f"{label}.pdf"
                chart.savefig(os.path.join(CHART_DIRECTORY, filename), format="pdf", bbox_inches="tight")
                filenames.append(filename)
                plt.close(chart)

    # --- Aggregated chart: all HEIs, all countries combined ---
    # Mirrors the equivalent block in generate_tables.py, which never lost
    # this step -- the chart generator only kept the public/private split
    # below, so the plain "_by_country" chart stopped being regenerated.
    group_by = ["country"]
    rename_map = {"country": "Country", "score": "Score"}
    stats_df = get_dataframe_stats(consolidated_dataframe, target_column, group_by, rename_map, avg)
    stats_df["Country"] = stats_df["Country"].map(lambda x: get_country_name(x))
    data = stats_df.sort_values(by=columns_to_sort, ascending=ascending)
    if not data.empty:
        label = f"{title_prefix.replace(' ', '_').lower()}_by_country"
        x_axis_label_agg = f"{title_prefix} (avg)" if avg else f"{title_prefix} (%)"
        chart = make_bar_chart(
            data, "Country", x_axis_label_agg, "Country",
            f"{title_prefix} by Country ({'avg' if avg else '%'})", legend_title, color_map
        )
        filename = f"{label}.pdf"
        chart.savefig(os.path.join(CHART_DIRECTORY, filename), format="pdf", bbox_inches="tight")
        filenames.append(filename)
        plt.close(chart)

    # --- Aggregated charts by country and category ---
    group_by = ["country", "Category"]
    rename_map = {"country": "Country", "score": "Score"}
    stats_df = get_dataframe_stats(
        consolidated_dataframe, target_column, group_by, rename_map, avg
    )
    stats_df["Country"] = stats_df["Country"].map(lambda x: get_country_name(x))
    for category in ["public", "private"]:
        data = stats_df[stats_df["Category"] == category].drop(columns=["Category"]).sort_values(
            by=columns_to_sort, ascending=ascending
        )
        if data.empty:
            continue

        label = f"{title_prefix.replace(' ', '_').lower()}_by_country_{category}"
        x_axis_label_agg = f"{title_prefix} (avg)" if avg else f"{title_prefix} (%)"
        chart = make_bar_chart(
            data, "Country", x_axis_label_agg, "Country",
            f"{title_prefix} at {category.capitalize()} HEIs by Country ({'avg' if avg else '%'})", legend_title, color_map
        )
        filename = f"{label}.pdf"
        chart.savefig(os.path.join(CHART_DIRECTORY, filename), format="pdf", bbox_inches="tight")
        filenames.append(filename)
        plt.close(chart)

    # Write a LaTeX input file with \includegraphics entries for each chart.
    input_text: str = "".join(f"""
\\begin{{figure}}[H]
    \\centering
    \\includegraphics[width=1\\textwidth]{{figs/dnssec/{f}}}
    \\caption{{{f.split('.')[0].replace('_', ' ').title()}}}
    \\label{{fig:{f.split('.')[0]}}}
\\end{{figure}} \n\n""" for f in filenames)
    save_chart(input_text, f"{title_prefix.replace(' ', '_').lower()}_INPUTS.txt")
