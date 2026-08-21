import os
import re

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from src.analyzer.setup import CHART_DIRECTORY
from src.analyzer.utils import get_country
from src.analyzer.chart_style import (
    CATEGORICAL, GREY, GREY_ALT, GRID, INK, INK_SOFT, figure_legend, panel_title,
)

# ---------------------------------------------------------------------------
# CA family unification
# Each tuple: (canonical_name, [substring_patterns_lowercase])
# Evaluated in order; first match wins.
# ---------------------------------------------------------------------------
_CA_FAMILY_RULES = [
    ("Let's Encrypt",       ["let's encrypt", "letsencrypt", " r3", " r10", " r11", " r14",
                              " e1", " e5", " e6", "k12", "k13"]),
    ("GÉANT",               ["geant", "géant", "terena"]),
    ("Sectigo",             ["sectigo", "comodo", "usertrust"]),
    ("DigiCert",            ["digicert", "thawte", "verisign", "geotrust", "rapidssl"]),
    ("Starfield (GoDaddy)", ["godaddy", "starfield"]),
    ("GlobalSign",          ["globalsign"]),
    ("Microsoft",           ["microsoft"]),
    ("ZeroSSL",             ["zerossl"]),
]


def _unify_ca_family(raw_name: str) -> str:
    """Return the canonical family name for a raw CA string."""
    if not isinstance(raw_name, str):
        return "Others"
    lower = raw_name.lower()
    for canonical, patterns in _CA_FAMILY_RULES:
        if any(p in lower for p in patterns):
            return canonical
    return raw_name  # keep as-is; will fall into Others if not in top-N


def get_ca_stats(dataframe):
    dataframe = dataframe.copy()
    dataframe["certificate_authority"] = dataframe["certificate_authority"].fillna("Unknown")

    # Unify CA names into canonical families BEFORE counting
    dataframe["certificate_authority"] = dataframe["certificate_authority"].apply(_unify_ca_family)

    ca_counts = dataframe["certificate_authority"].value_counts()
    top_5_cas = ca_counts.nlargest(5).index.tolist()

    dataframe["ca_grouped"] = dataframe["certificate_authority"].apply(
        lambda x: x if x in top_5_cas else "Others"
    )

    def compute_stats(groupby_cols, level_name):
        stats = (
            dataframe.groupby(groupby_cols)["ca_grouped"]
            .value_counts()
            .unstack(fill_value=0)
            .reset_index()
        )
        all_buckets = top_5_cas + (["Others"] if "Others" not in top_5_cas else [])
        for bucket in all_buckets:
            if bucket not in stats.columns:
                stats[bucket] = 0
        stats["total_certificates"] = stats[all_buckets].sum(axis=1)
        for ca in all_buckets:
            stats[f"{ca}_percent"] = (stats[ca] / stats["total_certificates"] * 100).round(2)
        stats["level"] = level_name
        return stats

    stats_by_nuts = compute_stats(["country", "NUTS2_Label"], "nuts")
    stats_by_nuts.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)
    stats_by_nuts["Category"] = None

    stats_by_nuts_category = compute_stats(["country", "NUTS2_Label", "Category"], "nuts_category")
    stats_by_nuts_category.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)

    stats_by_country_category = compute_stats(["country", "Category"], "country_category")
    stats_by_country_category["nuts"] = None

    stats_by_country = compute_stats(["country"], "country")
    stats_by_country["nuts"] = None
    stats_by_country["Category"] = None

    consolidated_stats = pd.concat(
        [stats_by_nuts, stats_by_nuts_category, stats_by_country_category, stats_by_country],
        axis=0, ignore_index=True,
    )
    return consolidated_stats


def plot_ca_pie_charts(dataframe, level, title, country_filter=None):
    if level == "country_category":
        dataframe = dataframe[
            (dataframe["level"] == "country_category") & (dataframe["country"] == country_filter)
        ]
        fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.4))
        categories = ["private", "public"]
    elif level == "country":
        dataframe = dataframe[dataframe["level"] == "country"]
        # Two columns rather than one.  Stacked in a single column this figure
        # came out several pages tall, which LaTeX cannot place: at
        # \textwidth it was taller than the text block by a factor of three.
        n_rows = (len(dataframe) + 1) // 2
        fig, grid = plt.subplots(n_rows, 2, figsize=(11.0, 3.5 * n_rows))
        axes = list(grid.flatten()) if hasattr(grid, "flatten") else [grid]
        for spare in axes[len(dataframe):]:
            spare.axis("off")
        categories = None
    else:
        raise ValueError("Invalid level. Use 'country_category', or 'country'.")

    ca_columns = [
        col for col in dataframe.columns
        if col.endswith("_percent") and col != "total_certificates"
    ]
    ca_labels = [col.replace("_percent", "") for col in ca_columns]

    # Grey is reserved for the residual slots, so a reader never mistakes
    # "Unknown" for a real certificate authority.  Everything else comes from
    # the validated palette, in a fixed order, so the same CA keeps the same
    # colour across every pie in the thesis.
    residual = {"others": GREY, "other": GREY, "unknown": GREY_ALT}
    unique_ca = sorted(set(ca_labels), key=ca_labels.index)
    real = [c for c in unique_ca if str(c).strip().lower() not in residual]
    color_mapping = {}
    for i, label in enumerate(real):
        color_mapping[label] = CATEGORICAL[i % len(CATEGORICAL)]
    for label in unique_ca:
        color_mapping.setdefault(label, residual.get(str(label).strip().lower(), GREY))

    def _totals(row):
        """Absolute number of certificates behind the percentages, when the
        scan recorded it.  A share of 4% over 24 institutions is one
        institution; the count says so and the percentage does not."""
        try:
            return int(round(float(row.get("total_certificates"))))
        except (TypeError, ValueError):
            return None

    def _draw(ax, values, labels, total):
        """One pie: big slices labelled inside, small ones outside on a leader
        line, stacked so the leaders fan out instead of piling up."""
        colors = [color_mapping[lbl] for lbl in labels]
        wedges, _ = ax.pie(
            values, labels=None, colors=colors, startangle=90, counterclock=False,
            wedgeprops={"edgecolor": "white", "linewidth": 1.6},
        )
        ax.set_aspect("equal")
        outside = {1: [], -1: []}
        for wedge, label, value in zip(wedges, labels, values):
            pct = float(value)
            ang = np.radians((wedge.theta1 + wedge.theta2) / 2)
            count = None if total is None else int(round(pct / 100.0 * total))
            text = f"{pct:.1f}%" if count is None else f"{count} ({pct:.1f}%)"
            if pct >= 12:
                ax.text(0.58 * np.cos(ang), 0.58 * np.sin(ang), text, size=11,
                        weight="bold", color="white", ha="center", va="center", zorder=6)
            else:
                # Only the part before the first parenthesis: the full name
                # stays in the legend, and "WE1 (Google Trust Services from
                # US)" on a leader line would run into the next panel.
                short = str(label).split(" (")[0]
                outside[1 if np.cos(ang) >= 0 else -1].append((ang, f"{short}  {text}"))
        for side, items in outside.items():
            if not items:
                continue
            items.sort(key=lambda t: -np.sin(t[0]))
            top = 0.30 * (len(items) - 1) / 2 + 0.62
            for j, (ang, text) in enumerate(items):
                ax.annotate(text, xy=(0.97 * np.cos(ang), 0.97 * np.sin(ang)),
                            xytext=(1.16 * side, top - 0.30 * j), size=9.5,
                            weight="bold", color=INK, annotation_clip=False,
                            ha="left" if side > 0 else "right", va="center", zorder=6,
                            arrowprops=dict(arrowstyle="-", color=INK_SOFT, lw=1.0,
                                            shrinkA=0, shrinkB=3))

    if level == "country_category":
        for i, category in enumerate(categories):
            subset = dataframe[dataframe["Category"] == category]
            if subset.empty:
                axes[i].axis("off")
                continue
            row = subset.iloc[0]
            values = row[ca_columns].values
            valid_indices = values > 0
            filtered_values = values[valid_indices]
            filtered_labels_i = [ca_labels[j] for j in range(len(ca_labels)) if valid_indices[j]]
            total = _totals(row)
            _draw(axes[i], filtered_values, filtered_labels_i, total)
            panel_title(axes[i], f"{category.capitalize()} HEIs", total)

        patches = [
            mpatches.Patch(facecolor=color_mapping[label], edgecolor="white", label=label)
            for label in sorted(color_mapping.keys())
        ]
        figure_legend(fig, handles=patches, title="Certificate Authorities",
                      ncol=3, fontsize=10.5, y=0.02)

    elif level == "country":
        for i, (_, row) in enumerate(dataframe.iterrows()):
            values = row[ca_columns].values
            valid_indices = values > 0
            filtered_values = values[valid_indices]
            filtered_labels_i = [ca_labels[j] for j in range(len(ca_labels)) if valid_indices[j]]
            total = _totals(row)
            _draw(axes[i], filtered_values, filtered_labels_i, total)
            panel_title(axes[i], get_country(row["country"]), total)

        patches = [
            mpatches.Patch(facecolor=color_mapping[label], edgecolor="white", label=label)
            for label in sorted(color_mapping.keys())
        ]
        figure_legend(fig, handles=patches, title="Certificate Authorities",
                      ncol=3, fontsize=10.5, y=0.015)

    # No figure title: the LaTeX caption names the figure.  `title` stays in
    # the signature so the callers and the caption text are unchanged.
    plt.tight_layout()
    return fig


def generate_ca_pie_charts(dataframe):
    total_countries = dataframe["country"].unique()
    for country in total_countries:
        cols_to_remove = [
            col for col in dataframe.columns
            if col.endswith("_percent") and dataframe[col].sum() == 0
        ]
        dataframe.drop(columns=cols_to_remove, inplace=True)

        fig = plot_ca_pie_charts(
            dataframe,
            "country_category",
            f"Certificate Authorities Distribution in {get_country(country)} by Category",
            country,
        )
        file_name = f"ca_distribution_in_{country}_by_category.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)

    for country in total_countries:
        country_data = dataframe[dataframe["country"] == country]
        cols_to_remove = [
            col for col in country_data.columns
            if col.endswith("_percent") and country_data[col].sum() == 0
        ]
        country_data = country_data.drop(columns=cols_to_remove)
        fig = plot_ca_pie_charts(
            country_data, "country",
            f"Certificate Authorities Distribution in {get_country(country)}",
        )
        file_name = f"ca_distribution_in_{country}.pdf"
        path_to_save = os.path.join(CHART_DIRECTORY, file_name)
        fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
        plt.close(fig)

    # Combined chart across all countries (one pie subplot per country, side
    # by side). The per-country loop above only saves one country at a time
    # ("in_{country}.pdf") -- this call reuses plot_ca_pie_charts' existing
    # "country" branch, which already lays out all rows in the passed-in
    # dataframe as separate subplots, so passing the unfiltered dataframe here
    # produces the combined "_by_country" figure that stopped regenerating.
    fig = plot_ca_pie_charts(
        dataframe, "country",
        "Certificate Authorities Distribution by Country",
    )
    file_name = "ca_distribution_by_country.pdf"
    path_to_save = os.path.join(CHART_DIRECTORY, file_name)
    fig.savefig(path_to_save, format="pdf", bbox_inches="tight")
    plt.close(fig)


def make_ca_report(dataframe):
    stats = get_ca_stats(dataframe)
    generate_ca_pie_charts(stats)


if __name__ == "__main__":
    pass
