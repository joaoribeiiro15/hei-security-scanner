import os

import pandas as pd
import matplotlib.pyplot as plt
from src.analyzer.report.utils import get_country, _ensure_country, _ensure_nuts2_label
from src.analyzer.report.setup import RESULT_FILE_PATH, TABLE_DIRECTORY, CHART_DIRECTORY
from src.analyzer.report.chart_style import (
    GREY, figure_legend, recessive_axes,
)

HTTP_VERSIONS = ["http/3", "http/2", "http/1.1", "http/1.0"]


def prepare_http_stats(dataframe):
    dataframe = _ensure_country(dataframe)
    dataframe = _ensure_nuts2_label(dataframe)

    if "Category" in dataframe.columns:
        dataframe["Category"] = dataframe["Category"].str.lower()

    dataframe["protocol_http"] = dataframe["protocol_http"].replace({"h2": "http/2", "h3": "http/3"})

    stats_by_nuts = dataframe.groupby(["country", "NUTS2_Label"])["protocol_http"].value_counts().unstack().fillna(0)
    stats_by_nuts_category = dataframe.groupby(["country", "NUTS2_Label", "Category"])["protocol_http"].value_counts().unstack().fillna(0)
    stats_by_country = dataframe.groupby("country")["protocol_http"].value_counts().unstack().fillna(0)

    for df in [stats_by_nuts, stats_by_nuts_category, stats_by_country]:
        for version in HTTP_VERSIONS:
            if version not in df.columns:
                df[version] = 0

    stats_by_nuts = stats_by_nuts[HTTP_VERSIONS].copy()
    stats_by_nuts_category = stats_by_nuts_category[HTTP_VERSIONS].copy()
    stats_by_country = stats_by_country[HTTP_VERSIONS].copy()

    stats_by_nuts["total_schools"] = stats_by_nuts.sum(axis=1)
    stats_by_nuts_category["total_schools"] = stats_by_nuts_category.sum(axis=1)
    stats_by_country["total_schools"] = stats_by_country.sum(axis=1)

    for version in HTTP_VERSIONS:
        stats_by_nuts[f"{version}_percent"] = (stats_by_nuts[version] / stats_by_nuts["total_schools"] * 100).round(2)
        stats_by_nuts_category[f"{version}_percent"] = (
            stats_by_nuts_category[version] / stats_by_nuts_category["total_schools"] * 100
        ).round(2)
        stats_by_country[f"{version}_percent"] = (stats_by_country[version] / stats_by_country["total_schools"] * 100).round(2)

    stats_by_nuts = stats_by_nuts.reset_index().rename(columns={"NUTS2_Label": "nuts"})
    stats_by_nuts["Category"] = None
    stats_by_nuts["level"] = "nuts"

    stats_by_nuts_category = stats_by_nuts_category.reset_index().rename(columns={"NUTS2_Label": "nuts"})
    stats_by_nuts_category["level"] = "nuts_category"

    stats_by_country = stats_by_country.reset_index()
    stats_by_country["nuts"] = None
    stats_by_country["Category"] = None
    stats_by_country["level"] = "country"

    return pd.concat([stats_by_nuts, stats_by_nuts_category, stats_by_country], axis=0, ignore_index=True)


def latex_http_table(dataframe, level, title, label):
    if level == "nuts":
        columns_to_display = ["nuts"] + [f"{col}_percent" for col in HTTP_VERSIONS]
        dataframe = dataframe.sort_values(by=[f"{col}_percent" for col in HTTP_VERSIONS], ascending=False)
        rename_map = {
            "nuts": "NUTS2",
            **{f"{col}_percent": col.upper().replace("/", "-") for col in HTTP_VERSIONS},
        }
    elif level == "country":
        columns_to_display = ["country"] + [f"{col}_percent" for col in HTTP_VERSIONS]
        dataframe = dataframe.sort_values(by=[f"{col}_percent" for col in HTTP_VERSIONS], ascending=False)
        rename_map = {
            "country": "Country",
            **{f"{col}_percent": col.upper().replace("/", "-") for col in HTTP_VERSIONS},
        }
    else:
        raise ValueError("Invalid level. Use 'nuts' or 'country'.")

    dataframe = dataframe[columns_to_display].rename(columns=rename_map)
    h_temp = [col.upper().replace("/", "-") for col in HTTP_VERSIONS]
    cols_to_remove = [col for col in h_temp if col in dataframe.columns and dataframe[col].sum() == 0]
    dataframe = dataframe.drop(columns=cols_to_remove)

    column_headers = " & ".join(f"\\makecell{{{col}}}" for col in dataframe.columns)

    table_rows = "\n".join(
        f"            {row[0] if level != 'country' else get_country(row[0])} & " + " & ".join(
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


def generate_http_adoption_tables(stats_dataframe):
    countries = stats_dataframe["country"].unique()

    for country in countries:
        filtered_df = stats_dataframe[(stats_dataframe["country"] == country) & (stats_dataframe["level"] == "nuts")]
        nuts2_table = latex_http_table(
            filtered_df,
            "nuts",
            f"HTTP Version Adoption in {get_country(country)} by NUTS2 (\\%)",
            f"nuts2_http_version_adoption_in_{country.lower()}",
        )
        path_to_save = os.path.join(TABLE_DIRECTORY, f"sh_http_version_adoption_in_{country}_by_nuts2.tex")
        with open(path_to_save, "w", encoding="utf-8") as tex_file:
            tex_file.write(nuts2_table)

        for category in ["public", "private"]:
            filtered_df = stats_dataframe[
                (stats_dataframe["country"] == country)
                & (stats_dataframe["level"] == "nuts_category")
                & (stats_dataframe["Category"] == category)
            ]
            nuts2_table = latex_http_table(
                filtered_df,
                "nuts",
                f"HTTP Version Adoption at {category.capitalize()} HEIs in {get_country(country)} by NUTS2 (\\%)",
                f"nuts2_http_version_adoption_in_{country.lower()}_{category}",
            )
            path_to_save = os.path.join(TABLE_DIRECTORY, f"sh_http_version_adoption_in_{country}_by_nuts2_{category}.tex")
            with open(path_to_save, "w", encoding="utf-8") as tex_file:
                tex_file.write(nuts2_table)

    filtered_df = stats_dataframe[stats_dataframe["level"] == "country"]
    country_table = latex_http_table(
        filtered_df,
        "country",
        "HTTP Version Adoption by Country (\\%)",
        "country_http_version_adoption",
    )
    path_to_save = os.path.join(TABLE_DIRECTORY, "sh_http_version_adoption_by_country.tex")
    with open(path_to_save, "w", encoding="utf-8") as tex_file:
        tex_file.write(country_table)


def plot_http_adoption_chart(dataframe, level, title, country_filter=None, category_filter=None):
    if level == "nuts":
        if not country_filter:
            raise ValueError("Country filter is required for NUTS level.")
        dataframe = dataframe[(dataframe["country"] == country_filter) & (dataframe["level"] == "nuts")]
        y_column = "nuts"
        columns_to_plot = [f"{col}_percent" for col in HTTP_VERSIONS]
        num_rows = dataframe[y_column].nunique()
        size_box = (10, max(6, num_rows * 0.32))
    elif level == "nuts_category":
        if not country_filter:
            raise ValueError("Country filter is required for NUTS category level.")
        if not category_filter:
            raise ValueError("Category filter is required for NUTS category level.")
        dataframe = dataframe[
            (dataframe["country"] == country_filter)
            & (dataframe["level"] == "nuts_category")
            & (dataframe["Category"] == category_filter)
        ]
        y_column = "nuts"
        columns_to_plot = [f"{col}_percent" for col in HTTP_VERSIONS]
        num_rows = dataframe[y_column].nunique()
        size_box = (10, max(6, num_rows * 0.32))
    elif level == "country":
        dataframe = dataframe[dataframe["level"] == "country"].copy()
        dataframe["country"] = dataframe["country"].apply(get_country)
        y_column = "country"
        columns_to_plot = [f"{col}_percent" for col in HTTP_VERSIONS]
        num_rows = dataframe[y_column].nunique()
        size_box = (10, max(3, num_rows * 0.8))
    else:
        raise ValueError("Invalid level. Use 'nuts', 'nuts_category' or 'country'.")

    dataframe = dataframe.sort_values(by=columns_to_plot, ascending=True)
    dataframe = dataframe[[y_column] + columns_to_plot].set_index(y_column)
    if dataframe.empty:
        return None
    fig, ax = plt.subplots(figsize=size_box)

    custom_colors = {
        "http/3_percent": "#009E73",
        "http/2_percent": "#0072B2",
        "http/1.1_percent": "#E69F00",
        "http/1.0_percent": "#D55E00",
    }

    dataframe.plot(
        kind='barh',
        stacked=True,
        color=[custom_colors.get(col, GREY) for col in columns_to_plot],
        edgecolor="white",
        linewidth=1.2,
        ax=ax,
    )

    ax.set_xlabel("Adoption of HTTP Versions (%)", fontsize=12)
    ax.set_ylabel("NUTS2" if level in ["nuts", "nuts_category"] else "Country", fontsize=12)
    ax.tick_params(labelsize=11)
    # No title: the LaTeX caption names the figure.
    figure_legend(ax, labels=HTTP_VERSIONS, handles=ax.containers,
                  title="HTTP Version", ncol=4, y=-0.17)
    recessive_axes(ax, grid_axis="x")

    plt.tight_layout()
    return fig


def generate_http_adoption_chart(dataframe):
    total_countries = dataframe["country"].unique()
    for country in total_countries:
        fig = plot_http_adoption_chart(
            dataframe,
            "nuts",
            f"HTTP Version Adoption by NUTS2 in {get_country(country)}",
            country,
        )
        if fig is not None:
            file_name = f"sh_http_version_adoption_by_nuts2_in_{country}.pdf"
            path_to_save = os.path.join(CHART_DIRECTORY, file_name)
            fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
            plt.close(fig)

        for category in ["public", "private"]:
            fig = plot_http_adoption_chart(
                dataframe,
                "nuts_category",
                f"HTTP Version Adoption at {category.capitalize()} HEIs in {get_country(country)} by NUTS2",
                country,
                category,
            )
            if fig is not None:
                file_name = f"sh_http_version_adoption_by_nuts2_in_{country}_{category}.pdf"
                path_to_save = os.path.join(CHART_DIRECTORY, file_name)
                fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
                plt.close(fig)

    fig = plot_http_adoption_chart(dataframe, "country", "HTTP Version Adoption by Country")
    if fig is not None:
        file_name = "sh_http_version_adoption_by_country.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)


def make_http_version_adoption():
    df = pd.read_csv(RESULT_FILE_PATH)
    stats = prepare_http_stats(df)
    generate_http_adoption_tables(stats)
    generate_http_adoption_chart(stats)


if __name__ == "__main__":
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)

    make_http_version_adoption()
