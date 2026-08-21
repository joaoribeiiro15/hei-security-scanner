import os

import pandas as pd
import matplotlib.pyplot as plt

from src.analyzer.setup import TABLE_DIRECTORY, CHART_DIRECTORY
from src.analyzer.utils import get_country
from src.analyzer.chart_style import (
    GREY, STATUS, figure_legend, recessive_axes,
)

_STATUSES = ["Valid", "At Risk", "Invalid"]

# Status colours are reserved project-wide: the same green/amber/red means
# the same thing in every figure, and is never reused as a series colour.
_STATUS_COLORS = {
    "Valid": STATUS["good"],
    "At Risk": STATUS["weak"],
    "Invalid": STATUS["bad"],
}


def _assign_cert_status(dataframe):
    """Add a cert_status column with values 'Valid', 'At Risk', or 'Invalid'."""
    df = dataframe.copy()
    if "cert_at_risk" not in df.columns:
        df["cert_at_risk"] = False
    at_risk = df["valid_certificate"] & df["cert_at_risk"].fillna(False).astype(bool)
    valid = df["valid_certificate"] & ~at_risk
    df["cert_status"] = "Invalid"
    df.loc[valid, "cert_status"] = "Valid"
    df.loc[at_risk, "cert_status"] = "At Risk"
    return df


def _compute_stats(df, group_cols):
    stats = df.groupby(group_cols + ["cert_status"]).size().unstack(fill_value=0).reset_index()
    for s in _STATUSES:
        if s not in stats.columns:
            stats[s] = 0
    stats = stats[group_cols + _STATUSES].copy()
    stats["total_schools"] = stats[_STATUSES].sum(axis=1)
    for s in _STATUSES:
        col = s.lower().replace(" ", "_") + "_percent"
        stats[col] = (stats[s] / stats["total_schools"] * 100).round(2)
    return stats


def get_valid_certificates_stats(dataframe):
    dataframe = _assign_cert_status(dataframe)

    stats_by_nuts = _compute_stats(dataframe, ["country", "NUTS2_Label"])
    stats_by_nuts.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)
    stats_by_nuts["Category"] = None
    stats_by_nuts["level"] = "nuts"

    stats_by_nuts_category = _compute_stats(dataframe, ["country", "NUTS2_Label", "Category"])
    stats_by_nuts_category.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)
    stats_by_nuts_category["level"] = "nuts_category"

    stats_by_country_category = _compute_stats(dataframe, ["country", "Category"])
    stats_by_country_category["nuts"] = None
    stats_by_country_category["level"] = "country_category"

    stats_by_country = _compute_stats(dataframe, ["country"])
    stats_by_country["nuts"] = None
    stats_by_country["Category"] = None
    stats_by_country["level"] = "country"

    consolidated_stats = pd.concat(
        [stats_by_nuts, stats_by_nuts_category, stats_by_country_category, stats_by_country],
        axis=0, ignore_index=True
    )

    return consolidated_stats


def latex_algorithm_table(dataframe, level, title, label):
    percent_cols = [col for col in dataframe.columns if isinstance(col, str) and col.endswith("_percent")]

    if level == "nuts":
        dataframe = dataframe[dataframe["level"] == "nuts"]
        columns_to_display = ["nuts"] + percent_cols
        rename_map = {"nuts": "NUTS2"}
    elif level == "nuts_category":
        dataframe = dataframe[dataframe["level"] == "nuts_category"]
        columns_to_display = ["nuts"] + percent_cols
        rename_map = {"nuts": "NUTS2"}
    elif level == "country":
        dataframe = dataframe[dataframe["level"] == "country"]
        columns_to_display = ["country"] + percent_cols
        rename_map = {"country": "Country"}
    else:
        raise ValueError("Invalid level. Use 'nuts', 'nuts_category', or 'country'.")

    sort_cols = list(reversed(percent_cols))
    dataframe = dataframe.sort_values(by=sort_cols, ascending=False)

    rename_map.update({
        col: col.replace("_percent", "").replace("_", " ").title()
        for col in percent_cols
    })

    cols_to_remove = [c for c in percent_cols if dataframe[c].sum() == 0]
    columns_to_display = [col for col in columns_to_display if col not in cols_to_remove]

    dataframe = dataframe[columns_to_display].rename(columns=rename_map)
    column_headers = " & ".join(f"\\makecell{{{col}}}" for col in dataframe.columns)

    table_rows = "\n".join(
        f"            {row[0] if (level != 'country' and level != 'country_category') else get_country(row[0])} & "
        + " & ".join(
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


def generate_valid_certificates_tables(stats_dataframe):
    countries = stats_dataframe["country"].unique()
    for country in countries:
        nuts_data = stats_dataframe[(stats_dataframe["country"] == country) & (stats_dataframe["level"] == "nuts")]
        nuts2_table = latex_algorithm_table(
            nuts_data, "nuts",
            f"Valid Certificate Distribution in {get_country(country)} by NUTS2 (\\%)",
            f"valid_certificate_distribution_{country.lower()}_nuts",
        )
        path_to_save = os.path.join(TABLE_DIRECTORY, f"valid_certificate_distribution_in_{country}_by_nuts2.tex")
        with open(path_to_save, "w", encoding="utf-8") as tex_file:
            tex_file.write(nuts2_table)

        for cat_name, cat_label in [("private", "private"), ("public", "public")]:
            nuts_cat_data = stats_dataframe[
                (stats_dataframe["country"] == country) &
                (stats_dataframe["level"] == "nuts_category") &
                (stats_dataframe["Category"] == cat_name)
            ]
            nuts2_cat_table = latex_algorithm_table(
                nuts_cat_data, "nuts_category",
                f"Valid Certificate Distribution at {cat_name.capitalize()} HEIs in {get_country(country)} by NUTS2 (\\%)",
                f"valid_certificate_distribution_{country.lower()}_nuts_{cat_label}",
            )
            path_to_save = os.path.join(
                TABLE_DIRECTORY, f"valid_certificate_distribution_in_{country}_by_nuts2_{cat_label}.tex"
            )
            with open(path_to_save, "w", encoding="utf-8") as tex_file:
                tex_file.write(nuts2_cat_table)

    country_data = stats_dataframe[stats_dataframe["level"] == "country"]
    country_table = latex_algorithm_table(
        country_data, "country",
        "Valid Certificate Distribution by Country (\\%)",
        "valid_certificate_distribution_by_country",
    )
    path_to_save = os.path.join(TABLE_DIRECTORY, "valid_certificate_distribution_by_country.tex")
    with open(path_to_save, "w", encoding="utf-8") as tex_file:
        tex_file.write(country_table)


def plot_key_algorithm_chart(dataframe, level, title, country_filter=None, category_filter=None):
    percent_cols = [s.lower().replace(" ", "_") + "_percent" for s in _STATUSES]
    display_cols = [s for s in _STATUSES]

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

    rename_map = {col: col.replace("_percent", "").replace("_", " ").title() for col in percent_cols}
    available_percent_cols = [c for c in percent_cols if c in dataframe.columns]
    available_display = [rename_map[c] for c in available_percent_cols]

    plot_df = dataframe[[y_column] + available_percent_cols].rename(columns=rename_map)
    plot_df = plot_df.set_index(y_column)
    plot_df.sort_values(by="Valid", ascending=True, inplace=True)

    color_list = [_STATUS_COLORS.get(col, GREY) for col in available_display]

    fig, ax = plt.subplots(figsize=size_box)
    plot_df.plot(kind="barh", stacked=True, color=color_list, edgecolor="white",
                 linewidth=1.2, ax=ax)

    for container in ax.containers:
        for rect, value in zip(container, container.datavalues):
            if value > 0:
                height = rect.get_height()
                width = rect.get_width()
                x_pos = rect.get_x() + width / 2
                y_pos = rect.get_y() + height / 2
                if width > 3:
                    face_color = rect.get_facecolor()[:3]
                    brightness = sum(c * w for c, w in zip(face_color, [0.299, 0.587, 0.114]))
                    text_color = "black" if brightness > 0.5 else "white"
                    ax.text(x_pos, y_pos, f"{value:.1f}", ha="center", va="center",
                            fontsize=10, color=text_color)

    ax.set_xlabel("Valid Certificates (%)", fontsize=12)
    ax.set_ylabel("NUTS2" if level != "country" else "Country", fontsize=12)
    # No title: the LaTeX caption names the figure.
    figure_legend(ax, labels=available_display, handles=ax.containers,
                  title="Status", ncol=3, y=-0.15)
    ax.tick_params(axis="y", labelsize=11)
    recessive_axes(ax, grid_axis="x")

    plt.tight_layout()
    return fig


def generate_valid_certificate_chart(dataframe):
    total_countries = dataframe["country"].unique()
    for country in total_countries:
        fig = plot_key_algorithm_chart(
            dataframe, "nuts",
            f"Valid Certificates in {get_country(country)} by NUTS2",
            country,
        )
        file_name = f"valid_certificate_distribution_in_{country}_by_nuts2.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)

        for category in ["public", "private"]:
            fig = plot_key_algorithm_chart(
                dataframe, "nuts_category",
                f"Valid Certificates at {category.capitalize()} HEIs in {get_country(country)} by NUTS2",
                country, category,
            )
            file_name = f"valid_certificate_distribution_in_{country}_by_nuts2_{category}.pdf"
            path_to_save = os.path.join(CHART_DIRECTORY, file_name)
            fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
            plt.close(fig)

    for country in total_countries:
        country_data = dataframe[dataframe["country"] == country]
        fig = plot_key_algorithm_chart(
            country_data, "country",
            f"Valid Certificates in {get_country(country)}",
        )
        file_name = f"valid_certificate_distribution_in_{country}.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)

    fig = plot_key_algorithm_chart(dataframe, "country", "Valid Certificate Distribution by Country")
    file_name = "valid_certificate_distribution_by_country.pdf"
    path_to_save = os.path.join(CHART_DIRECTORY, file_name)
    fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
    plt.close(fig)


def make_valid_certificate_report(dataframe):
    stats = get_valid_certificates_stats(dataframe)

    generate_valid_certificates_tables(stats)
    generate_valid_certificate_chart(stats)


if __name__ == "__main__":
    pass
