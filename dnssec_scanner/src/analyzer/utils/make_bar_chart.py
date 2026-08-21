from typing import Tuple

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from src.analyzer.utils.chart_style import (
    GRID, INK, figure_legend, recessive_axes, series_colours,
)
from src.analyzer.utils.color_format_chart_bar import format_bar_annotations
from src.analyzer.utils.wrap_labels import wrap_labels

CHART_WIDTH: int = 8
MIN_HEIGHT: int = 6


def make_bar_chart(stats_df: pd.DataFrame, y_column: str, x_label: str, y_label: str, title: str, legend_title: str,
                   color_map: list[str] = None,
                   legend_position: str = None, legend_columns: int = None, bbox_to_anchor: Tuple[int, int] = None,
                   ) -> Figure:
    """Build and return a stacked horizontal bar chart figure.

    The chart is returned without being displayed or saved so that callers
    can choose the output format and destination independently.

    ``title`` is accepted and deliberately IGNORED: every chart here is
    included in LaTeX inside a ``figure`` environment whose ``\\caption``
    already names it, so drawing the title into the PDF only duplicates the
    caption and eats vertical space.  The parameter is kept so the three
    report modules that call this function do not have to change, and so the
    string stays available for the caption text.

    ``color_map`` is optional now: when it is omitted the colours come from
    the validated palette in ``chart_style``, keyed on the series name, so
    "Valid" is the same green in every figure of the thesis.
    """
    legend_columns = 4 if legend_columns is None else legend_columns

    columns_to_plot = [col for col in stats_df.columns.tolist() if col not in [y_column]]
    stats_df.set_index(y_column, inplace=True)

    colours = color_map if color_map else series_colours(columns_to_plot)

    # Scale chart height dynamically so that bars do not overlap on large datasets.
    size_box = (CHART_WIDTH, max(MIN_HEIGHT, int(len(stats_df) * 0.35)))
    fig, ax = plt.subplots(figsize=size_box)

    stats_df.plot(kind='barh', stacked=True, edgecolor="white", linewidth=1.2,
                  ax=ax, color=colours)
    format_bar_annotations(ax)

    ax.set_xlabel(x_label, fontsize=12, color=INK)
    ax.set_ylabel(y_label, fontsize=12, color=INK)
    ax.tick_params(labelsize=11)

    # ax.set_yticklabels(wrap_labels(stats_df.index))
    # Uncomment the line above to enable automatic label wrapping on the y-axis
    # when NUTS2 region names are too long to fit without truncation.

    # Legend below the plot, framed and centred.  It used to sit above the
    # axes only because the title was there; with the title gone it belongs
    # under the chart, where it cannot be mistaken for one.
    figure_legend(ax, labels=columns_to_plot, handles=ax.containers,
                  title=legend_title, ncol=legend_columns, y=-0.12)

    recessive_axes(ax, grid_axis="x")
    plt.tight_layout()
    return fig
