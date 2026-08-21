import os

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from src.analyzer.setup import TABLE_DIRECTORY, CHART_DIRECTORY
from src.analyzer.utils import get_country
from src.analyzer.chart_style import (
    GREY, GRID, INK, PAIR_A, PAIR_B, Radar, figure_legend, finish,
    panel_title, recessive_axes, series_colours,
)


def get_algorithm_stats(dataframe):
    def extract_algorithm_size(value):
        if pd.isna(value):
            return "Unknown"
        parts = value.split()
        return " ".join(parts[:2]) if len(parts) > 1 else value

    dataframe["key_algorithm"] = dataframe["key_size"].apply(extract_algorithm_size)
    dataframe.sort_values(by=["key_algorithm"], inplace=True, ascending=False)
    stats_by_nuts = dataframe.groupby(["country", "NUTS2_Label", "key_algorithm"]).size().unstack(
        fill_value=0).reset_index()
    stats_by_nuts.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)
    stats_by_nuts["Category"] = None

    stats_by_nuts_category = dataframe.groupby(
        ["country", "NUTS2_Label", "Category", "key_algorithm"]).size().unstack(fill_value=0).reset_index()
    stats_by_nuts_category.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)

    stats_by_country_category = dataframe.groupby(["country", "Category", "key_algorithm"]).size().unstack(
        fill_value=0).reset_index()
    stats_by_country_category["nuts"] = None

    stats_by_country = dataframe.groupby(["country", "key_algorithm"]).size().unstack(fill_value=0).reset_index()
    stats_by_country["nuts"] = None
    stats_by_country["Category"] = None

    key_algorithms = dataframe["key_algorithm"].unique()
    for df in [stats_by_nuts, stats_by_nuts_category, stats_by_country_category, stats_by_country]:
        for key in key_algorithms:
            if key not in df:
                df[key] = 0

    for df in [stats_by_nuts, stats_by_nuts_category, stats_by_country_category, stats_by_country]:
        df["total_schools"] = df[key_algorithms].sum(axis=1)

    for key in key_algorithms:
        stats_by_nuts[f"{key}_percent"] = (stats_by_nuts[key] / stats_by_nuts["total_schools"] * 100).round(2)
        stats_by_nuts_category[f"{key}_percent"] = (
                stats_by_nuts_category[key] / stats_by_nuts_category["total_schools"] * 100).round(2)
        stats_by_country_category[f"{key}_percent"] = (
                stats_by_country_category[key] / stats_by_country_category["total_schools"] * 100).round(2)
        stats_by_country[f"{key}_percent"] = (stats_by_country[key] / stats_by_country["total_schools"] * 100).round(2)

    stats_by_nuts["level"] = "nuts"
    stats_by_nuts_category["level"] = "nuts_category"
    stats_by_country_category["level"] = "country_category"
    stats_by_country["level"] = "country"

    consolidated_stats = pd.concat([stats_by_nuts, stats_by_nuts_category, stats_by_country_category, stats_by_country],
                                   axis=0, ignore_index=True)

    cols_to_remove = [col for col in key_algorithms if consolidated_stats[col].sum() == 0]
    cols_to_remove += [f"{col}_percent" for col in cols_to_remove]
    consolidated_stats.drop(columns=cols_to_remove, inplace=True)

    return consolidated_stats


def latex_algorithm_table(dataframe, level, title, label):
    if level == "nuts":
        columns_to_display = ["nuts"] + [col for col in dataframe.columns if col.endswith("_percent")]
        dataframe = dataframe[dataframe["level"] == "nuts"]
        rename_map = {
            "nuts": "NUTS2",
        }
    elif level == "nuts_category":
        columns_to_display = ["nuts"] + [col for col in dataframe.columns if col.endswith("_percent")]
        dataframe = dataframe[dataframe["level"] == "nuts_category"]
        rename_map = {
            "nuts": "NUTS2",
        }
    elif level == "country":
        dataframe = dataframe[dataframe["level"] == "country"]
        columns_to_display = ["country"] + [col for col in dataframe.columns if col.endswith("_percent")]
        rename_map = {
            "country": "Country",
        }
    else:
        raise ValueError("Invalid level. Use 'nuts' or 'country'.")

    dataframe = dataframe.sort_values(
        by=[col for col in reversed([col for col in dataframe.columns if col.endswith("_percent")])],
        ascending=False)
    rename_map.update(**{col: col.replace("_percent", "") for col in dataframe.columns if col.endswith("_percent")})
    cols_to_remove = [c for c in [col for col in dataframe.columns if col.endswith("_percent")] if
                      dataframe[c].sum() == 0]
    columns_to_display = [col for col in columns_to_display if col not in cols_to_remove]
    dataframe = dataframe[columns_to_display].rename(columns=rename_map)
    column_headers = " & ".join(
        "\\makecell{" + col.replace(" ", "\\\\") + "}" for col in dataframe.columns
    )

    table_rows = "\n".join(
        f"            {row[0] if (level != 'country' and level != 'country_category') else get_country(row[0])} & " + " & ".join(
            "-" if pd.isna(value) or value == 0
            else f"{int(value)}" if isinstance(value, (float, int)) and value == int(value)
            else f"{value:.2f}" if isinstance(value, float)
            else str(value)
            for value in row[1:]
        ) + " \\\\"
        for row in dataframe.itertuples(index=False, name=None)
    )

    latex_table = f"""
\\begin{{table}}[H]
    \\centering
    \\caption{{{title}}}
    \\label{{tab:{label}}}
    \\rowcolors{{2}}{{white}}{{gray!15}}
    \\begin{{tabularx}}{{\\textwidth}}{{X{'c' * len(dataframe.columns)}}}
        \\toprule
        {column_headers} \\\\
        \\midrule
{table_rows}
        \\bottomrule
    \\end{{tabularx}}
\\end{{table}}
        """
    return latex_table


def generate_algorithm_tables(stats_dataframe):
    countries = stats_dataframe["country"].unique()
    for country in countries:
        nuts_data = stats_dataframe[(stats_dataframe["country"] == country) & (stats_dataframe["level"] == "nuts")]
        nuts2_table = latex_algorithm_table(nuts_data, "nuts",
                                            f"Key Algorithm Distribution in {get_country(country)} by NUTS2 (\\%)",
                                            f"key_algorithm_distribution_{country.lower()}_nuts")
        path_to_save = os.path.join(TABLE_DIRECTORY, f"key_algorithm_distribution_in_{country}_by_nuts2.tex")
        with open(path_to_save, "w", encoding="utf-8") as tex_file:
            tex_file.write(nuts2_table)
        nuts_data = stats_dataframe[(stats_dataframe["country"] == country) &
                                    (stats_dataframe["level"] == "nuts_category") &
                                    (stats_dataframe["Category"] == "private")]
        nuts2_table = latex_algorithm_table(nuts_data, "nuts_category",
                                            f"Key Algorithm Distribution at Private HEIs in {get_country(country)} by NUTS2 (\\%)",
                                            f"key_algorithm_distribution_{country.lower()}_nuts_private")
        path_to_save = os.path.join(TABLE_DIRECTORY, f"key_algorithm_distribution_in_{country}_by_nuts2_private.tex")
        with open(path_to_save, "w", encoding="utf-8") as tex_file:
            tex_file.write(nuts2_table)
        nuts_data = stats_dataframe[(stats_dataframe["country"] == country) &
                                    (stats_dataframe["level"] == "nuts_category") &
                                    (stats_dataframe["Category"] == "public")]
        nuts2_table = latex_algorithm_table(nuts_data, "nuts_category",
                                            f"Key Algorithm Distribution at Public HEIs in {get_country(country)} by NUTS2 (\\%)",
                                            f"key_algorithm_distribution_{country.lower()}_nuts_public")
        path_to_save = os.path.join(TABLE_DIRECTORY, f"key_algorithm_distribution_in_{country}_by_nuts2_public.tex")
        with open(path_to_save, "w", encoding="utf-8") as tex_file:
            tex_file.write(nuts2_table)

    country_data = stats_dataframe[stats_dataframe["level"] == "country"]
    country_table = latex_algorithm_table(country_data, "country", "Key Algorithm Distribution by Country (\\%)",
                                          "key_algorithm_distribution_by_country")
    path_to_save = os.path.join(TABLE_DIRECTORY, "key_algorithm_distribution_by_country.tex")
    with open(path_to_save, "w", encoding="utf-8") as tex_file:
        tex_file.write(country_table)


def create_radar_chart(dataframe):
    algorithms = [col for col in dataframe.columns if col.endswith("_percent")]
    total_algorithms = len(algorithms)
    angles = np.linspace(0, 2 * np.pi, total_algorithms, endpoint=False).tolist()
    angles.append(angles[0])

    countries = dataframe["country"].unique()

    for country in countries:
        country_data = dataframe[(dataframe["country"] == country) & (dataframe["level"] == "country_category")]

        data_cols = [col for col in country_data.columns if col.endswith("_percent")]
        labels = [col.replace("_percent", "") for col in data_cols]
        private_usage = country_data[country_data["Category"] == "private"][data_cols].values.flatten()
        public_usage = country_data[country_data["Category"] == "public"][data_cols].values.flatten()

        series = []
        if private_usage.size:
            series.append(("Private HEIs", private_usage, PAIR_B, 1))
        if public_usage.size:
            series.append(("Public HEIs", public_usage, PAIR_A, 0))

        # Spokes where every series is zero carry no data: put the radial tick
        # labels and the footnote there rather than over a polygon.
        step = 360.0 / max(len(labels), 1)
        empty = [i for i in range(len(labels))
                 if all(float(v[i]) <= 0 for _, v, _, _ in series)] if series else []
        tick_angle = empty[-1] * step if empty else step / 2
        note_angle = empty[0] * step if empty else step * 0.35

        fig = plt.figure(figsize=(9.8, 8.8))
        ax = fig.add_subplot(111, polar=True)
        # Logarithmic radial axis, same as the protocol radar: one algorithm
        # dominates and a linear axis would flatten everything else.
        radar = Radar(ax, labels, [1, 5, 10, 25, 50, 100], scale="log", rmax=118,
                      cat_size=14, tick_size=11, cat_pad=1.075, tick_angle=tick_angle)

        for name, values, colour, idx in series:
            radar.plot(name, list(values), idx, color=colour, lw=2.6, markersize=8)
        for name, values, colour, idx in series:
            for i, value in enumerate(values):
                if value <= 0:
                    continue
                radar.value_label(i, float(value), colour,
                                  dtheta=10 if idx else -10,
                                  dr=0.10 if float(value) >= 10 else 0.18, size=11.5)

        if empty:
            radar.note(", ".join(labels[i] for i in empty) + " = 0%\n(plotted at the centre)",
                       note_angle, radar.rmax * 0.5, size=10.5)

        figure_legend(ax, ncol=2, fontsize=13, y=-0.07)

        filename = os.path.join(CHART_DIRECTORY, f"key_algorithm_radar_in_{country.lower()}.pdf")
        finish(fig, filename)


def plot_key_algorithm_chart(dataframe, level, title, country_filter=None, category_filter=None):
    if level == "nuts":
        if not country_filter:
            raise ValueError("Country filter is required for NUTS level.")
        dataframe = dataframe[(dataframe["country"] == country_filter) & (dataframe["level"] == "nuts")]
        y_column = "nuts"
        num_rows = dataframe[y_column].nunique()
        size_box = (10, max(6, num_rows * 0.35))
    elif level == "nuts_category":
        if not country_filter:
            raise ValueError("Country filter is required for NUTS category level.")
        if not category_filter:
            raise ValueError("Category filter is required for NUTS category level.")
        dataframe = dataframe[
            (dataframe["country"] == country_filter) &
            (dataframe["level"] == "nuts_category") &
            (dataframe["Category"] == category_filter)
        ]
        y_column = "nuts"
        num_rows = dataframe[y_column].nunique()
        size_box = (10, max(6, num_rows * 0.35))
    elif level == "country":
        dataframe = dataframe[dataframe["level"] == "country"].copy()
        dataframe["country"] = dataframe["country"].apply(get_country)
        y_column = "country"
        num_rows = dataframe[y_column].nunique()
        size_box = (10, max(3, num_rows * 0.8))
    else:
        raise ValueError("Invalid level. Use 'nuts', 'nuts_category' or 'country'.")
    rename_map = {col: col.replace("_percent", "") for col in dataframe.columns if col.endswith("_percent")}

    columns_to_display = [col for col in dataframe.columns if col.endswith("_percent")]
    cols_to_remove = [c for c in [col for col in dataframe.columns if col.endswith("_percent")] if
                      dataframe[c].sum() == 0]
    columns_to_plot = [col for col in columns_to_display if col not in cols_to_remove]
    dataframe = dataframe[[y_column] + columns_to_display].rename(columns=rename_map)
    algorithm_order = [
        "RSA 1024", "RSA 2048", "RSA 3072", "RSA 4096",
        "EC 256", "EC 384", "EC 521"
    ]
    columns_to_plot = sorted(
        [col.replace("_percent", "") for col in columns_to_plot],
        key=lambda x: algorithm_order.index(x) if x in algorithm_order else len(algorithm_order)
    )
    dataframe = dataframe[[y_column] + columns_to_plot].set_index(y_column)
    fig, ax = plt.subplots(figsize=size_box)

    # ggplot2 colorblind-friendly palette
    # Elliptic-curve family in greens, RSA family warming up as the key gets
    # shorter, so strength reads off the colour.  Every hue is from the
    # validated palette in chart_style; the two that were too light to survive
    # greyscale printing (#44AA99, #88CCEE, #DDCC77) were replaced.
    custom_colors = {
        "EC 521": "#117733",    # dark green
        "EC 384": "#009E73",    # green
        "EC 256": "#0072B2",    # blue
        "RSA 4096": "#7570B3",  # purple
        "RSA 3072": "#A6761D",  # ochre
        "RSA 2048": "#D55E00",  # vermillion
        "RSA 1024": "#882255",  # wine
        "Unknown": GREY,        # grey is reserved for the residual slot
    }
    color_list = [custom_colors.get(col, GREY) for col in columns_to_plot]

    dataframe.plot(kind='barh', stacked=True, color=color_list,
                   edgecolor="white", linewidth=1.2, ax=ax)

    for container in ax.containers:
        for rect, value in zip(container, container.datavalues):
            if value > 0:
                height = rect.get_height()
                width = rect.get_width()
                x_pos = rect.get_x() + width / 2
                y_pos = rect.get_y() + height / 2

                if width > 3:
                    face_color = rect.get_facecolor()[:3]
                    brightness = sum([c * w for c, w in zip(face_color, [0.299, 0.587, 0.114])])
                    text_color = "black" if brightness > 0.5 else "white"
                    ax.text(x_pos, y_pos, f"{value:.1f}", ha="center", va="center",
                            fontsize=10, color=text_color)

    ax.set_xlabel("Key Algorithms (%)", fontsize=12)
    ax.set_ylabel("NUTS2" if level == "nuts" else "Country", fontsize=12)
    # No title: the LaTeX caption names the figure.
    figure_legend(ax, labels=columns_to_plot, handles=ax.containers,
                  title="Key Algorithms", ncol=6, y=-0.15)
    ax.tick_params(axis="y", labelsize=11)
    recessive_axes(ax, grid_axis="x")

    plt.tight_layout()
    return fig


def generate_key_algorithm_chart(dataframe):
    # Combined chart across all countries. Mirrors generate_algorithm_tables()'s
    # "country" block above, which never lost this step -- only the chart
    # generator's per-country loop below survived a past refactor, so the
    # plain "_by_country" chart (all countries together) stopped regenerating.
    fig = plot_key_algorithm_chart(
        dataframe, "country",
        "Key Algorithm Distribution by Country",
    )
    file_name = "key_algorithm_distribution_by_country.pdf"
    path_to_save = os.path.join(CHART_DIRECTORY, file_name)
    fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
    plt.close(fig)

    total_countries = dataframe["country"].unique()
    for country in total_countries:
        fig = plot_key_algorithm_chart(
            dataframe,
            "nuts",
            f"Key Algorithm in {get_country(country)} by NUTS2",
            country,
        )
        file_name = f"key_algorithm_distribution_in_{country}_by_nuts2.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)

        for category in ["public", "private"]:
            fig = plot_key_algorithm_chart(
                dataframe,
                "nuts_category",
                f"Key Algorithm at {category.capitalize()} HEIs in {get_country(country)} by NUTS2",
                country,
                category,
            )
            file_name = f"key_algorithm_distribution_in_{country}_by_nuts2_{category}.pdf"
            path_to_save = os.path.join(CHART_DIRECTORY, file_name)
            fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
            plt.close(fig)

    for country in total_countries:
        country_data = dataframe[dataframe["country"] == country]
        fig = plot_key_algorithm_chart(
            country_data, "country",
            f"Key Algorithm in {get_country(country)}",
        )
        file_name = f"key_algorithm_distribution_in_{country}.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)


def make_algorithm_report(dataframe):
    stats = get_algorithm_stats(dataframe)
    generate_algorithm_tables(stats)
    create_radar_chart(stats)
    generate_key_algorithm_chart(stats)



if __name__ == "__main__":
    pass
