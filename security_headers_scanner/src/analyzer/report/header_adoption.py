import os
import textwrap
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon
from matplotlib.colors import Normalize
import matplotlib.cm as cm
from mpl_toolkits.axes_grid1 import make_axes_locatable
import numpy as np
import pandas as pd
from src.analyzer.report.setup import RESULT_FILE_PATH, TABLE_DIRECTORY, CHART_DIRECTORY, ROOT_DIRECTORY, \
    RESULT_PLATFORM_FILE_PATH
from src.analyzer.report.utils import get_country, get_reverse_country, _ensure_country, _ensure_nuts2_label, _ensure_eter_id
from src.config import config, EXPECTED_HEADERS_KEY
from src.analyzer.report.chart_style import (
    GREY, GRID, INK, PAIR_A, PAIR_B, Radar, figure_legend, finish,
    legend_handles_pair, panel_title,
)

header_short_names = {
    "strict-transport-security": {"latex": "\\gls{hsts}", "normal": "HSTS"},
    "x-xss-protection": {"latex": "XXP", "normal": "XXP"},
    "x-frame-options": {"latex": "\\gls{xfo}", "normal": "XFO"},
    "x-content-type-options": {"latex": "XCTO", "normal": "XCTO"},
    "referrer-policy": {"latex": "RP", "normal": "RP"},
    "cross-origin-opener-policy": {"latex": "\\gls{coop}", "normal": "COOP"},
    "cross-origin-embedder-policy": {"latex": "\\gls{coep}", "normal": "COEP"},
    "cross-origin-resource-policy": {"latex": "\\gls{corp}", "normal": "CORP"},
    "access-control-allow-origin": {"latex": "\\gls{cors}", "normal": "CORS"},
    "content-security-policy": {"latex": "\\gls{csp}", "normal": "CSP"},
    "set-cookie": {"latex": "SC", "normal": "SC"},
}





def get_stats(dataframe):
    dataframe = _ensure_country(dataframe)
    dataframe = _ensure_nuts2_label(dataframe)
    dataframe = _ensure_eter_id(dataframe)

    # Normalize Category to lowercase so downstream filters ("public", "private") match
    if "Category" in dataframe.columns:
        dataframe = dataframe.copy()
        dataframe["Category"] = dataframe["Category"].str.lower()

    expected_headers = [col.replace("_presence", "") for col in dataframe.columns if "_presence" in col]

    stats_by_nuts = dataframe.groupby(["country", "NUTS2_Label"]).agg(
        total_schools=("ETER_ID", "count"),
        **{f"{header}_present": (f"{header}_presence", "sum") for header in expected_headers},
        **{f"{header}_strong": (f"{header}_config", lambda x: (x == "Strong").sum()) for header in expected_headers},
        **{f"{header}_weak": (f"{header}_config", lambda x: (x == "Weak").sum()) for header in expected_headers}
    ).reset_index()
    stats_by_nuts.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)
    stats_by_nuts["Category"] = None

    stats_by_nuts_category = dataframe.groupby(["country", "NUTS2_Label", "Category"]).agg(
        total_schools=("ETER_ID", "count"),
        **{f"{header}_present": (f"{header}_presence", "sum") for header in expected_headers},
        **{f"{header}_strong": (f"{header}_config", lambda x: (x == "Strong").sum()) for header in expected_headers},
        **{f"{header}_weak": (f"{header}_config", lambda x: (x == "Weak").sum()) for header in expected_headers}
    ).reset_index()
    stats_by_nuts_category.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)

    stats_by_country = dataframe.groupby(["country"]).agg(
        total_schools=("ETER_ID", "count"),
        **{f"{header}_present": (f"{header}_presence", "sum") for header in expected_headers},
        **{f"{header}_strong": (f"{header}_config", lambda x: (x == "Strong").sum()) for header in expected_headers},
        **{f"{header}_weak": (f"{header}_config", lambda x: (x == "Weak").sum()) for header in expected_headers}
    ).reset_index()
    stats_by_country["nuts"] = None
    stats_by_country["Category"] = None
    stats_by_country["platform"] = None

    stats_by_country_category = dataframe.groupby(["country", "Category"]).agg(
        total_schools=("ETER_ID", "count"),
        **{f"{header}_present": (f"{header}_presence", "sum") for header in expected_headers},
        **{f"{header}_strong": (f"{header}_config", lambda x: (x == "Strong").sum()) for header in expected_headers},
        **{f"{header}_weak": (f"{header}_config", lambda x: (x == "Weak").sum()) for header in expected_headers}
    ).reset_index()
    stats_by_country_category["nuts"] = None

    stats_by_country_platform = dataframe.groupby(["country", "platform"]).agg(
        total_schools=("ETER_ID", "count"),
        **{f"{header}_present": (f"{header}_presence", "sum") for header in expected_headers},
        **{f"{header}_strong": (f"{header}_config", lambda x: (x == "Strong").sum()) for header in expected_headers},
        **{f"{header}_weak": (f"{header}_config", lambda x: (x == "Weak").sum()) for header in expected_headers}
    ).reset_index()
    stats_by_country_platform["nuts"] = None
    stats_by_country_platform["Category"] = None

    stats_by_country_category_platform = dataframe.groupby(["country", "Category", "platform"]).agg(
        total_schools=("ETER_ID", "count"),
        **{f"{header}_present": (f"{header}_presence", "sum") for header in expected_headers},
        **{f"{header}_strong": (f"{header}_config", lambda x: (x == "Strong").sum()) for header in expected_headers},
        **{f"{header}_weak": (f"{header}_config", lambda x: (x == "Weak").sum()) for header in expected_headers}
    ).reset_index()
    stats_by_country_category_platform["nuts"] = None

    all_dfs = [
        stats_by_nuts, stats_by_nuts_category, stats_by_country_category,
        stats_by_country, stats_by_country_category_platform, stats_by_country_platform
    ]

    for df in all_dfs:
        for header in expected_headers:
            df[f"{header}_present_percent"] = (
                (df[f"{header}_present"] / df["total_schools"]) * 100
            ).fillna(0).replace([np.inf, -np.inf], 0).round(2)
            df[f"{header}_strong_percent"] = (
                (df[f"{header}_strong"] / df[f"{header}_present"]) * 100
            ).fillna(0).replace([np.inf, -np.inf], 0).round(2)
            df[f"{header}_weak_percent"] = (
                (df[f"{header}_weak"] / df[f"{header}_present"]) * 100
            ).fillna(0).replace([np.inf, -np.inf], 0).round(2)

    stats_by_nuts["level"] = "nuts"
    stats_by_nuts_category["level"] = "nuts_category"
    stats_by_country_category["level"] = "country_category"
    stats_by_country["level"] = "country"
    stats_by_country_category_platform["level"] = "country_category_platform"
    stats_by_country_platform["level"] = "country_platform"

    consolidated_stats = pd.concat(all_dfs, axis=0, ignore_index=True)
    return consolidated_stats


def latex_header_table(dataframe, level, title, label, config_weak=False):
    expected_headers = list(config[EXPECTED_HEADERS_KEY].keys())
    expected_headers = [header.lower() for header in expected_headers]
    if level == "nuts":
        region = "nuts"
        rename_map = {
            "nuts": "NUTS2",
            **{f"{header}_present_percent": f"{header_short_names.get(header, header)['latex']}" for header in expected_headers},
            **{f"{header}_weak_percent": f"{header_short_names.get(header, header)['latex']} Weak" for header in expected_headers},
        }
    elif level == "nuts_category":
        region = "nuts"
        rename_map = {
            "nuts": "NUTS2",
            **{f"{header}_present_percent": f"{header_short_names.get(header, header)['latex']}" for header in expected_headers},
            **{f"{header}_weak_percent": f"{header_short_names.get(header, header)['latex']} Weak" for header in expected_headers},
        }
    elif level == "country":
        region = "country"
        rename_map = {
            "country": "Country",
            **{f"{header}_present_percent": f"{header_short_names.get(header, header)['latex']}" for header in expected_headers},
            **{f"{header}_weak_percent": f"{header_short_names.get(header, header)['latex']} Weak" for header in expected_headers},
        }
    else:
        raise ValueError("Invalid level. Use 'nuts' or 'country'.")

    if config_weak:
        columns_to_display = [region] + [f"{header}_weak_percent" for header in expected_headers]
    else:
        columns_to_display = [region] + [f"{header}_present_percent" for header in expected_headers]

    columns_to_remove = [col for col in columns_to_display if dataframe[col].sum() == 0]
    columns_to_display = [col for col in columns_to_display if col not in columns_to_remove]
    dataframe = dataframe[columns_to_display].rename(columns=rename_map)

    column_headers = " & ".join(f"\\rotatebox{{90}}{{\\makecell{{{col}}}}}" for col in dataframe.columns)
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


def generate_header_table(stats_dataframe):
    countries = stats_dataframe["country"].unique()
    critical_headers_presence = ["content-security-policy_present_percent", "strict-transport-security_present_percent"]
    critical_headers_weak = ["content-security-policy_weak_percent", "strict-transport-security_weak_percent"]
    print(f"Countries: {countries}")

    def save_table(table, path):
        with open(path, "w", encoding="utf-8") as tex_file:
            tex_file.write(table)

    for country in countries:
        filtered_df = stats_dataframe[
            (stats_dataframe["country"] == country) & (stats_dataframe["level"] == "nuts")
        ].sort_values(by=critical_headers_presence, ascending=False)

        nuts2_table = latex_header_table(
            filtered_df, "nuts",
            f"Security Headers Adoption in {get_country(country)} by NUTS2 (\\%)",
            f"sh_adoption_{country.lower()}"
        )
        save_table(nuts2_table, os.path.join(TABLE_DIRECTORY, f"sh_adoption_in_{country}_by_nuts2.tex"))

        filtered_df.sort_values(by=critical_headers_weak, ascending=True, inplace=True)
        nuts2_table = latex_header_table(
            filtered_df, "nuts",
            f"Security Headers Weak Configuration in {get_country(country)} by NUTS2 (\\%)",
            f"sh_weak_config_{country.lower()}", True
        )
        save_table(nuts2_table, os.path.join(TABLE_DIRECTORY, f"sh_weak_config_in_{country}_by_nuts2.tex"))

        for category in ["public", "private"]:
            filtered_df = stats_dataframe[
                (stats_dataframe["country"] == country) &
                (stats_dataframe["level"] == "nuts_category") &
                (stats_dataframe["Category"] == category)
            ].sort_values(by=critical_headers_presence, ascending=False)

            nuts2_table = latex_header_table(
                filtered_df, "nuts",
                f"Security Headers Adoption at {category.capitalize()} HEIs in {get_country(country)} by NUTS2 (\\%)",
                f"sh_adoption_{country.lower()}_{category}"
            )
            save_table(nuts2_table, os.path.join(TABLE_DIRECTORY, f"sh_adoption_in_{country}_by_nuts2_{category}.tex"))

            filtered_df.sort_values(by=critical_headers_weak, ascending=True, inplace=True)
            nuts2_table = latex_header_table(
                filtered_df, "nuts",
                f"Security Headers Weak Configuration at {category.capitalize()} HEIs in {get_country(country)} by NUTS2 (\\%)",
                f"sh_weak_config_{country.lower()}_{category}", True
            )
            save_table(nuts2_table, os.path.join(TABLE_DIRECTORY, f"sh_weak_config_in_{country}_by_nuts2_{category}.tex"))

    filtered_df = stats_dataframe[stats_dataframe["level"] == "country"].sort_values(
        by=critical_headers_presence, ascending=False
    )
    country_table = latex_header_table(filtered_df, "country",
                                       "Security Headers Adoption by Country (\\%)", "sh_adoption_country")
    save_table(country_table, os.path.join(TABLE_DIRECTORY, "sh_adoption_by_country.tex"))

    filtered_df.sort_values(by=critical_headers_weak, ascending=True, inplace=True)
    country_table = latex_header_table(filtered_df, "country",
                                       "Security Headers Weak Configuration by Country (\\%)",
                                       "sh_weak_config_country", True)
    save_table(country_table, os.path.join(TABLE_DIRECTORY, "sh_weak_config_by_country.tex"))


def plot_heat_map(dataframe, level, title):
    expected_headers = list(config[EXPECTED_HEADERS_KEY].keys())
    expected_headers = [header.lower() for header in expected_headers]
    if level == "nuts":
        y_column = "nuts"
    elif level == "country":
        y_column = "country"
    else:
        raise ValueError("Invalid level. Use 'nuts' or 'country'.")

    presence_columns = [f"{header}_present_percent" for header in expected_headers]
    presence_columns = [col for col in presence_columns if dataframe[col].sum() > 0]
    weak_columns = [f"{header}_weak_percent" for header in expected_headers]
    dataframe = dataframe[[y_column] + presence_columns + weak_columns].set_index(y_column)

    fig, ax = plt.subplots(figsize=(11, max(len(dataframe), 6) * 0.5))
    num_y = len(dataframe)
    num_x = len(presence_columns)
    norm_blue = Normalize(vmin=0, vmax=100)
    norm_red = Normalize(vmin=0, vmax=100)
    cmap_blue = cm.Blues
    cmap_red = cm.Reds

    def get_text_color(rgb_color):
        r, g, b, _ = rgb_color
        brightness = (0.299 * r + 0.587 * g + 0.114 * b) * 255
        return "white" if brightness < 128 else "black"

    for i in range(num_y):
        for j in range(num_x):
            adoption_value = dataframe.iloc[i, j]
            weak_value = dataframe.iloc[i, j + num_x]
            x, y = j, i
            color_top = cmap_blue(norm_blue(adoption_value))
            triangle_top = [[x, y + 1], [x + 1, y + 1], [x + 1, y]]
            ax.add_patch(Polygon(triangle_top, closed=True, color=color_top, alpha=0.8))
            color_bottom = cmap_red(norm_red(weak_value))
            triangle_bottom = [[x, y + 1], [x, y], [x + 1, y]]
            ax.add_patch(Polygon(triangle_bottom, closed=True, color=color_bottom, alpha=0.8))
            text_color_top = get_text_color(color_top)
            text_color_bottom = get_text_color(color_bottom)
            af = "-" if adoption_value == 0 else f"{adoption_value:.0f}"
            wv = "-" if weak_value == 0 else f"{weak_value:.0f}"
            ax.text(x + 0.5, y + 0.75, f"{af}", ha="center", va="center", fontsize=10, color=text_color_top)
            ax.text(x + 0.5, y + 0.25, f"{wv}", ha="center", va="center", fontsize=10, color=text_color_bottom)

    # No title: the LaTeX caption names the figure.  `title` is kept as an
    # argument so the callers and the caption text stay unchanged.
    filtered_headers = [header for header in expected_headers if f"{header}_present_percent" in dataframe.columns]
    ax.set_xticks(np.arange(len(filtered_headers)) + 0.5)
    ax.set_xticklabels([header_short_names.get(header, header)["normal"] for header in filtered_headers], fontsize=11,
                       rotation=45, ha="right")
    ax.set_yticks(np.arange(num_y) + 0.5)

    def wrap_labels(labels, width=15):
        return ['\n'.join(textwrap.wrap(label, width)) for label in labels]

    ax.set_yticklabels(wrap_labels(dataframe.index if level == "nuts" else dataframe.index.map(get_country)), fontsize=11)
    ax.set_xlim(0, num_x)
    ax.set_ylim(0, num_y)
    plt.subplots_adjust(right=0.99)
    divider = make_axes_locatable(ax)
    cbar_ax1 = divider.append_axes("right", size="2%", pad=0.08)
    cbar_ax2 = divider.append_axes("right", size="2%", pad=0.6)
    cbar1 = plt.colorbar(cm.ScalarMappable(norm=norm_blue, cmap=cmap_blue), cax=cbar_ax1)
    cbar2 = plt.colorbar(cm.ScalarMappable(norm=norm_red, cmap=cmap_red), cax=cbar_ax2)
    cbar1.set_label("Adoption (%)", fontsize=11)
    cbar2.set_label("Weak Config. (%)", fontsize=11)
    ax.set_xlabel("Security Headers", fontsize=12)
    ax.set_ylabel("NUTS2" if level == "nuts" else "Country", fontsize=12)
    plt.tight_layout()
    return fig


def generate_heatmap(dataframe):
    # Combined heatmap across all countries. Mirrors generate_header_table()'s
    # "country" block above, which never lost this step -- only the chart
    # generator's per-country loops below survived a past refactor, so the
    # plain "_by_country" chart (all countries together) stopped regenerating.
    filtered_df = dataframe[dataframe["level"] == "country"]
    fig = plot_heat_map(
        filtered_df, "country",
        "Security Headers Adoption and Weak Config by Country (%)",
    )
    fig.savefig(
        os.path.join(CHART_DIRECTORY, "sh_adoption_weak_by_country.pdf"),
        format="pdf", bbox_inches="tight",
    )
    plt.close(fig)

    total_countries = dataframe["country"].unique()
    for country in total_countries:
        filtered_df = dataframe[(dataframe["country"] == country) & (dataframe["level"] == "nuts")]
        fig = plot_heat_map(filtered_df, "nuts",
                            f"Security Headers Adoption and Weak Config in {get_country(country)} by NUTS2 (%)")
        file_name = f"sh_adoption_weak_by_nuts2_in_{country}.pdf"
        fig.savefig(os.path.join(CHART_DIRECTORY, file_name), format="pdf", bbox_inches="tight")
        plt.close(fig)

        for category in ["public", "private"]:
            filtered_df = dataframe[
                (dataframe["country"] == country)
                & (dataframe["level"] == "nuts_category")
                & (dataframe["Category"] == category)
            ]
            fig = plot_heat_map(
                filtered_df,
                "nuts",
                f"Security Headers Adoption and Weak Config at {category.capitalize()} HEIs in {get_country(country)} by NUTS2 (%)",
            )
            file_name = f"sh_adoption_weak_by_nuts2_in_{country}_{category}.pdf"
            fig.savefig(os.path.join(CHART_DIRECTORY, file_name), format="pdf", bbox_inches="tight")
            plt.close(fig)

    for country in total_countries:
        filtered_df = dataframe[
            (dataframe["country"] == country) & (dataframe["level"] == "nuts")
        ]
        if filtered_df.empty:
            filtered_df = dataframe[
                (dataframe["country"] == country) & (dataframe["level"] == "country")
            ]
            level_key = "country"
        else:
            level_key = "nuts"
        fig = plot_heat_map(
            filtered_df, level_key,
            f"Security Headers Adoption and Weak Config in {get_country(country)} by NUTS2 (%)"
        )
        fig.savefig(
            os.path.join(CHART_DIRECTORY, f"sh_adoption_weak_in_{country}.pdf"),
            format="pdf", bbox_inches="tight"
        )
        plt.close(fig)


def create_radar_charts(kpi_data):
    highlight_positive = config["critical_headers"]
    highlight_deprecated = config["deprecated_headers"]
    headers = list(config["expected_headers"].keys())
    num_headers = len(headers)
    angles = np.linspace(0, 2 * np.pi, num_headers, endpoint=False).tolist()
    angles.append(angles[0])
    countries = kpi_data["country"].unique()

    # Short header names, wrapped, so the labels stay legible without pushing
    # the radar itself down to a postage stamp.  Same abbreviations as the
    # comparison tables, so the reader only learns them once.
    def _short(header):
        # header_short_names is keyed in lower case, while config lists the
        # headers in their canonical mixed case: without normalising, every
        # lookup missed and the radars fell back to the full names.
        return header_short_names.get(str(header).lower(), {}).get("normal", header)

    label_colours = {}
    short_labels = []
    for header in headers:
        text = _short(header)
        short_labels.append(text)
        if header in highlight_positive:
            label_colours[text] = "#1B7A3D"      # recommended
        elif header in highlight_deprecated:
            label_colours[text] = "#C62828"      # deprecated

    TICKS = [20, 40, 60, 80, 100]
    TICKS_SMALL = [20, 60, 100]      # small panels: five labels would collide

    def _quiet_angle(*series):
        """Angle of the spoke carrying the least data, so the radial tick
        labels land on empty grid rather than on top of a polygon."""
        step = 360.0 / max(len(short_labels), 1)
        totals = [sum(float(s[i]) for s in series if i < len(s))
                  for i in range(len(short_labels))]
        return totals.index(min(totals)) * step if totals else step / 2

    def _count(frame):
        if "total_schools" in frame.columns and not frame.empty:
            try:
                return int(frame["total_schools"].iloc[0])
            except (TypeError, ValueError):
                return None
        return None

    def _draw(ax, desktop, mobile, *, cat_size, tick_size, lw, markersize, small=False):
        radar = Radar(ax, short_labels, TICKS_SMALL if small else TICKS,
                      scale="linear", rmax=100,
                      cat_size=cat_size, tick_size=tick_size, cat_pad=1.09,
                      cat_colors=label_colours,
                      tick_angle=_quiet_angle(desktop, mobile))
        radar.plot("Desktop", list(desktop), 0, color=PAIR_A, lw=lw,
                   markersize=markersize, fill=0.13)
        radar.plot("Mobile", list(mobile), 1, color=PAIR_B, lw=lw,
                   markersize=markersize, fill=0)
        return radar

    # ------------------------------------------------ one figure per country
    for country in countries:
        country_data = kpi_data[
            (kpi_data["country"] == country) & (kpi_data["level"] == "country_category_platform")
        ]
        fig, axes = plt.subplots(1, 2, subplot_kw=dict(polar=True), figsize=(11.5, 5.6))
        fig.subplots_adjust(wspace=0.45, top=0.84, bottom=0.14)
        for i, category in enumerate(["public", "private"]):
            ax = axes[i]
            category_data = country_data[country_data["Category"] == category]
            if category_data.empty:
                ax.axis("off")
                continue
            data_cols = [col for col in category_data.columns if col.endswith("_present_percent")]
            desktop_usage = category_data[category_data["platform"] == "desktop"][data_cols].values.flatten()
            mobile_usage = category_data[category_data["platform"] == "mobile"][data_cols].values.flatten()
            if desktop_usage.size == 0 or mobile_usage.size == 0:
                ax.axis("off")
                continue
            _draw(ax, desktop_usage, mobile_usage,
                  cat_size=11, tick_size=8.5, lw=2.2, markersize=6.5)
            ax.set_title(
                f"{category.capitalize()} HEIs  (Total HEIs = "
                f"{_count(category_data[category_data['platform'] == 'desktop'])})",
                fontsize=13, fontweight="bold", color=INK, pad=26)

        # No figure title: the LaTeX caption names the figure.
        figure_legend(fig, handles=legend_handles_pair("Desktop", "Mobile"),
                      ncol=2, fontsize=12, y=0.02)
        filename = os.path.join(CHART_DIRECTORY, f"sh_adoption_by_category_{get_reverse_country(country)}.pdf")
        finish(fig, filename)

    # ------------------------------------- one figure per country, and a grid
    # The old layout stacked every country in a single column, which produced a
    # page several metres tall: at \textwidth it came out three pages long and
    # LaTeX could not place it.  Now each country is also written on its own,
    # sized for a 0.46\textwidth subfigure slot, plus a shared legend strip.
    per_country = []
    for country in countries:
        country_data = kpi_data[(kpi_data["country"] == country) & (kpi_data["level"] == "country_platform")]
        available_cols = [col for col in country_data.columns if col.endswith("_present_percent")]
        if not available_cols:
            continue
        desktop_usage = country_data[country_data["platform"] == "desktop"][available_cols].values.flatten()
        mobile_usage = country_data[country_data["platform"] == "mobile"][available_cols].values.flatten()
        if desktop_usage.size == 0 or mobile_usage.size == 0:
            continue
        per_country.append((country, desktop_usage, mobile_usage,
                            _count(country_data[country_data["platform"] == "desktop"])))

    SUB_W, SUB_H, SUB_AX = 2.72, 2.26, 1.56      # = 0.46\textwidth of the thesis
    for country, desktop_usage, mobile_usage, total in per_country:
        fig = plt.figure(figsize=(SUB_W, SUB_H))
        ax = fig.add_axes([0.5 - SUB_AX / SUB_W / 2, 1 - (1.10 + SUB_AX / 2) / SUB_H,
                           SUB_AX / SUB_W, SUB_AX / SUB_H], polar=True)
        _draw(ax, desktop_usage, mobile_usage,
              cat_size=7.5, tick_size=5.5, lw=1.3, markersize=3.4, small=True)
        finish(fig, os.path.join(CHART_DIRECTORY,
                                 f"sh_platform_{get_reverse_country(country).lower()}.pdf"))

    fig = plt.figure(figsize=(2.45, 0.34))
    leg = fig.legend(handles=legend_handles_pair("Desktop", "Mobile", scale=0.42),
                     loc="center", bbox_to_anchor=(0.5, 0.5), bbox_transform=fig.transFigure,
                     ncol=2, fontsize=8.5, frameon=True, borderpad=0.55,
                     handlelength=3.0, columnspacing=2.0)
    leg.get_frame().set_edgecolor(GRID)
    leg.get_frame().set_linewidth(1.0)
    finish(fig, os.path.join(CHART_DIRECTORY, "sh_platform_legend.pdf"))

    # The combined figure is kept for anyone still including it, but as a two
    # column grid that fits on one page instead of a single tall column.
    if per_country:
        rows = (len(per_country) + 1) // 2
        FIG_W, BLOCK, TOP0, AX_IN = 5.906, 2.67, 0.10, 1.61
        FIG_H = TOP0 + BLOCK * rows + 0.27
        fig = plt.figure(figsize=(FIG_W, FIG_H))
        for k, (country, desktop_usage, mobile_usage, total) in enumerate(per_country):
            xc, row = (0.25, 0.75)[k % 2], k // 2
            yc = 1 - (TOP0 + row * BLOCK + 1.28) / FIG_H
            ax = fig.add_axes([xc - AX_IN / FIG_W / 2, yc - AX_IN / FIG_H / 2,
                               AX_IN / FIG_W, AX_IN / FIG_H], polar=True)
            _draw(ax, desktop_usage, mobile_usage,
                  cat_size=8, tick_size=6, lw=1.5, markersize=4.2, small=True)
            caption = f"{get_country(country)} - Overall"
            if total is not None:
                caption += f"  (Total HEIs = {total})"
            fig.text(xc, 1 - (TOP0 + row * BLOCK + 0.20) / FIG_H, caption,
                     size=9, weight="bold", color=INK, ha="center", va="bottom")
        leg = fig.legend(handles=legend_handles_pair("Desktop", "Mobile", scale=0.45),
                         loc="lower center", bbox_to_anchor=(0.5, 0.10 / FIG_H),
                         bbox_transform=fig.transFigure, ncol=2, fontsize=9,
                         frameon=True, borderpad=0.8, handlelength=3.2, columnspacing=2.6)
        leg.get_frame().set_edgecolor(GRID)
        leg.get_frame().set_linewidth(1.2)
        finish(fig, os.path.join(CHART_DIRECTORY, "sh_adoption_by_platform_by_countries.pdf"))


def make_header_adoption():
    df = pd.read_csv(RESULT_FILE_PATH)
    stats = get_stats(df)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    generate_header_table(stats)
    generate_heatmap(stats)
    df_platform = pd.read_csv(RESULT_PLATFORM_FILE_PATH)
    stats_platform = get_stats(df_platform)
    create_radar_charts(stats_platform)


if __name__ == "__main__":
    make_header_adoption()
