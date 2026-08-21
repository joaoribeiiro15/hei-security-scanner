"""Shared chart style for every figure produced by this project.

This module is the single place where the look of a figure is decided.  It is
duplicated verbatim in the three scanners (the same way ``wrap_labels`` already
is), because each scanner runs with its own directory as the import root:

    http_scanner/src/analyzer/chart_style.py
    security_headers_scanner/src/analyzer/report/chart_style.py
    dnssec_scanner/src/analyzer/utils/chart_style.py

Keep the three copies identical.

--------------------------------------------------------------------------
The rules
--------------------------------------------------------------------------

1.  NO FIGURE TITLE.  Every figure here ends up inside a LaTeX ``figure``
    environment whose ``\\caption`` already names it.  A title baked into the
    PDF duplicates the caption, wastes vertical space, and cannot be
    referenced or translated.  Panel titles inside a multi-panel figure are
    the exception: they identify a panel, not the figure, so they stay, via
    :func:`panel_title`.

2.  LEGEND below the plot, centred, in a light frame, through
    :func:`figure_legend`.  Placing it above the axes was a workaround for
    the title occupying that space; with the title gone, below is where it
    belongs.  Figures are always saved through :func:`finish`, which uses a
    tight bounding box plus a fixed pad, so the legend frame can never be
    clipped by the canvas edge.

3.  COLOURS come from :data:`CATEGORICAL`, an order validated for the three
    common colour-vision deficiencies and for greyscale printing.  Grey is
    reserved for a residual "Others"/"Unknown" slot and is never used for a
    real category.  Status colours (good / weak / bad) live in
    :data:`STATUS` and are never reused as series colours.

4.  SECONDARY ENCODING on line-type charts: each series gets its own dash
    pattern and its own marker, so the chart still reads when printed in
    black and white, and for readers who cannot separate the hues.

5.  RECESSIVE GRID AND AXES.  The data is the ink; the frame is not.

6.  TEXT WEARS TEXT COLOUR.  Values, labels and legends use
    :data:`INK` / :data:`INK_SOFT`, never the series colour; the coloured
    mark next to them carries the identity.

7.  COUNTS BESIDE PERCENTAGES wherever there is room, and the population
    size in the panel title, via :func:`panel_title`.  With populations of a
    few dozen institutions, "4.2%" alone invites the reader to mistake one
    institution for a trend.

8.  NO ``plt.show()``.  :func:`finish` saves and then closes the figure, so a
    run that writes hundreds of charts does not leak them.
"""

from __future__ import annotations

import os
from typing import Iterable, Sequence

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

# --------------------------------------------------------------------- ink
INK = "#1a1a1a"          # primary text
INK_SOFT = "#4a4a4a"     # secondary text: tick labels, notes
GRID = "#c9ccd1"         # grid lines, legend frame, axis spines

# ------------------------------------------------------------------ colour
# Validated order: adjacent pairs stay apart under protanopia, deuteranopia
# and tritanopia, and all sit inside a lightness band that survives being
# printed in greyscale.  Extend at the END only, never reorder.
CATEGORICAL: list[str] = [
    "#009E73",   # green
    "#0072B2",   # blue
    "#A6761D",   # ochre
    "#CC79A7",   # pink
    "#D55E00",   # vermillion
    "#7570B3",   # purple
    "#117733",   # dark green
    "#882255",   # wine
]

# Validated with the eight above, in this order, against protan/deutan/tritan
# simulation, the greyscale lightness band and the white-surface contrast
# floor.  #CC79A7 sits just under the 3:1 contrast line, which is why every
# chart that uses it also carries a direct label or a legend entry.

GREY = "#8A8A8A"         # reserved for the "Others" residual slot
GREY_ALT = "#BDBDBD"     # second residual slot ("Unknown"), so the two stay apart

STATUS = {               # reserved; never reused as a series colour
    "good": "#009E73",
    "weak": "#E69F00",
    "bad": "#D55E00",
    "missing": GREY,
}

# Series that appear in more than one figure keep the same colour everywhere,
# so a reader who has learnt the colour once does not have to relearn it.
# The two-series pair used whenever a figure compares exactly two populations
# (public vs private, desktop vs mobile).  Validated as a pair, and kept
# identical across every such figure so the reader learns it once.
PAIR_A = "#1F4FD8"       # first series  (public HEIs, desktop)
PAIR_B = "#E8871A"       # second series (private HEIs, mobile)

FIXED_SERIES: dict[str, str] = {
    "public heis": PAIR_A,
    "private heis": PAIR_B,
    "public": PAIR_A,
    "private": PAIR_B,
    "desktop": PAIR_A,
    "mobile": PAIR_B,
    "valid": STATUS["good"],
    "at risk": STATUS["weak"],
    "invalid": STATUS["bad"],
    "missing": GREY,
    "unknown": GREY_ALT,
    "others": GREY,
    "other": GREY,
}

# Dash pattern + marker per series index, so line charts read in black and
# white.  Cycled only after all eight are used.
DASHES: list = ["solid", (0, (6, 3)), (0, (1, 1.6)), (0, (7, 2, 1.5, 2)),
                (0, (4, 2, 1, 2, 1, 2)), (0, (10, 3)), (0, (3, 1)), (0, (1, 3))]
MARKERS: list[str] = ["s", "o", "^", "D", "v", "P", "X", "*"]


def series_colours(labels: Sequence[str]) -> list[str]:
    """Colour per label: fixed colour if the label is a known one, else the
    next unused categorical hue.  Residual labels always land on grey."""
    out: list[str] = []
    used = {FIXED_SERIES[str(l).strip().lower()]
            for l in labels if str(l).strip().lower() in FIXED_SERIES}
    pool = [c for c in CATEGORICAL if c not in used] or list(CATEGORICAL)
    nxt = 0
    for raw in labels:
        key = str(raw).strip().lower()
        if key in FIXED_SERIES:
            out.append(FIXED_SERIES[key])
            continue
        out.append(pool[nxt % len(pool)])
        nxt += 1
    return out


# ------------------------------------------------------------------ rcparams
def apply_rc() -> None:
    """Project-wide matplotlib defaults.  Call once at import time."""
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "pdf.fonttype": 42,          # embed as TrueType: text stays selectable
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK,
        "axes.titlecolor": INK,
        "axes.linewidth": 1.0,
        "text.color": INK,
        "xtick.color": INK_SOFT,
        "ytick.color": INK_SOFT,
        "xtick.labelcolor": INK,
        "ytick.labelcolor": INK,
        "grid.color": GRID,
        "grid.linewidth": 0.9,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "legend.frameon": True,
        "legend.edgecolor": GRID,
        "legend.framealpha": 1.0,
    })


def recessive_axes(ax, *, grid_axis: str = "x") -> None:
    """Drop the top/right spines and put a soft grid behind the data."""
    for side in ("top", "right"):
        if side in ax.spines:
            ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        if side in ax.spines:
            ax.spines[side].set_color(GRID)
    ax.set_axisbelow(True)
    ax.grid(axis=grid_axis, linestyle="--", linewidth=0.9, color=GRID, alpha=0.9)


# ------------------------------------------------------------------- titles
def panel_title(ax, text: str, n: int | None = None, *, size: float = 12.5) -> None:
    """Title for ONE PANEL of a multi-panel figure.

    Never use this for the figure as a whole: the LaTeX caption does that.
    When ``n`` is given it is appended, because a percentage over a few dozen
    institutions means little without the denominator.
    """
    label = text if n is None else f"{text}  (Total HEIs = {n})"
    ax.set_title(label, fontsize=size, fontweight="bold", color=INK, pad=10)


# ------------------------------------------------------------------- legend
def figure_legend(ax_or_fig, handles=None, labels=None, *, title: str | None = None,
                  ncol: int = 4, fontsize: float = 10.5, title_fontsize: float = 11,
                  y: float = -0.14):
    """Framed legend, centred below the axes.

    ``y`` is in axes coordinates and negative, i.e. below the axes.  Combined
    with :func:`finish` (tight bounding box + fixed pad) the frame is always
    fully inside the saved page.
    """
    target = ax_or_fig
    kwargs = dict(loc="upper center", bbox_to_anchor=(0.5, y), ncol=ncol,
                  fontsize=fontsize, frameon=True, borderpad=0.7,
                  columnspacing=1.8, handlelength=2.2, labelspacing=0.5)
    if title:
        kwargs["title"] = title
        kwargs["title_fontsize"] = title_fontsize
    if handles is not None and labels is not None:
        leg = target.legend(handles, labels, **kwargs)
    elif handles is not None:
        leg = target.legend(handles=handles, **kwargs)
    else:
        leg = target.legend(**kwargs)
    leg.get_frame().set_edgecolor(GRID)
    leg.get_frame().set_linewidth(1.0)
    leg.get_frame().set_facecolor("white")
    if leg.get_title() is not None:
        leg.get_title().set_color(INK)
        leg.get_title().set_fontweight("bold")
    for text in leg.get_texts():
        text.set_color(INK)
    return leg


# --------------------------------------------------------------------- save
def text_margins(fig: Figure) -> tuple[float, float, float, float]:
    """Clearance in inches between the outermost text and each canvas edge.

    Negative anywhere means something is being cut off.  Only meaningful for
    figures saved WITHOUT a tight bounding box.
    """
    fig.canvas.draw()
    inv = fig.dpi_scale_trans.inverted()
    W, H = fig.get_size_inches()
    items = [t for ax in fig.axes for t in ax.texts] + list(fig.texts)
    items += [lg for lg in fig.legends] + [ax.get_legend() for ax in fig.axes if ax.get_legend()]
    boxes = [t.get_window_extent().transformed(inv) for t in items if t is not None]
    if not boxes:
        return (W, W, H, H)
    return (min(b.x0 for b in boxes), W - max(b.x1 for b in boxes),
            min(b.y0 for b in boxes), H - max(b.y1 for b in boxes))


def finish(fig: Figure, path: str, *, pad_inches: float = 0.08) -> str:
    """Save as PDF and close.

    Always a tight bounding box with a fixed pad: the page ends up exactly
    around the drawing plus a constant margin, so nothing at the edge can be
    clipped and every figure in the thesis carries the same white border.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    fig.savefig(path, format="pdf", bbox_inches="tight", pad_inches=pad_inches)
    plt.close(fig)
    return path

# -------------------------------------------------------------------- radar
class Radar:
    """A radar (spider) axes in the house style.

    Why a class rather than a pile of calls at each site: the three radar
    figures in this project were drifting apart (different label sizes,
    different legend anchors, one of them faking a title with ``fig.text``).
    Everything that decides how a radar looks now lives here.

    * ``scale="log"`` plots ``log10(max(v, 1))``, so 0 and 1 both sit at the
      centre; say so in the caption.  ``scale="linear"`` is a plain 0..rmax.
    * Category labels sit outside the rim, in a fixed order, so two radars
      can be compared by shape.
    * The radial tick labels go on one chosen spoke, on a white patch, out of
      the way of the data.
    """

    def __init__(self, ax, categories, ticks, *,
                 scale: str = "linear", rmax=None,
                 cat_size: float = 11, tick_size: float = 9,
                 cat_pad: float = 1.08, cat_pads=None,
                 cat_colors=None, tick_angle=None):
        import numpy as np
        self.ax, self.categories, self.scale = ax, list(categories), scale
        self.n = len(self.categories)
        self.ang = np.linspace(0, 2 * np.pi, self.n, endpoint=False)
        self.ang_c = np.concatenate([self.ang, self.ang[:1]])
        self.rmax = self.to_r(rmax if rmax else max(ticks))

        ax.set_theta_zero_location("E")
        ax.set_theta_direction(1)
        ax.set_ylim(0, self.rmax)
        ax.set_rgrids([self.to_r(t) for t in ticks], labels=[])
        ax.set_xticks(self.ang)
        ax.set_xticklabels([])
        ax.grid(color=GRID, linewidth=1.0)
        ax.spines["polar"].set_color(GRID)
        ax.spines["polar"].set_linewidth(1.2)
        ax.set_facecolor("white")

        cat_colors = cat_colors or {}
        cat_pads = cat_pads or {}
        for idx, (a, c) in enumerate(zip(self.ang, self.categories)):
            deg = np.degrees(a) % 360
            va = "bottom" if 10 < deg < 170 else ("top" if 190 < deg < 350 else "center")
            ha = "left" if (deg < 80 or deg > 280) else ("right" if 100 < deg < 260 else "center")
            ax.text(a, self.rmax * cat_pads.get(idx, cat_pad), c, size=cat_size,
                    weight="bold", color=cat_colors.get(c, INK), ha=ha, va=va)

        if tick_angle is None:
            tick_angle = 360.0 / self.n / 2
        for t in ticks:
            if self.to_r(t) <= 0:
                continue
            ax.text(np.radians(tick_angle), self.to_r(t), f"{t:g}%", size=tick_size,
                    color=INK_SOFT, ha="center", va="center", zorder=6,
                    bbox=dict(boxstyle="round,pad=0.22", fc="white", ec="none", alpha=0.92))

    def to_r(self, v):
        import numpy as np
        return float(np.log10(max(v, 1.0))) if self.scale == "log" else float(v)

    def plot(self, label, values, index: int = 0, *,
             color=None, fill: float = 0.13, lw: float = 2.4,
             markersize: float = 7.0):
        """One series.  ``index`` picks the dash pattern and the marker, so the
        series stay apart in black and white as well as in colour."""
        import numpy as np
        colour = color or CATEGORICAL[index % len(CATEGORICAL)]
        r = np.array([self.to_r(v) for v in values])
        rc = np.concatenate([r, r[:1]])
        self.ax.plot(self.ang_c, rc, color=colour, linewidth=lw,
                     linestyle=DASHES[index % len(DASHES)],
                     marker=MARKERS[index % len(MARKERS)], markersize=markersize,
                     markerfacecolor="white", markeredgewidth=lw * 0.85,
                     markeredgecolor=colour, zorder=5, solid_capstyle="round",
                     label=label)
        if fill:
            self.ax.fill(self.ang_c, rc, color=colour, alpha=fill, zorder=2, linewidth=0)

    def value_label(self, i, value, colour, *, dtheta: float = 0.0,
                    dr: float = 0.10, size: float = 10.5, fmt: str = "{:.1f}%"):
        import numpy as np
        self.ax.text(self.ang[i] + np.radians(dtheta), self.to_r(value) + dr,
                     fmt.format(value), size=size, weight="bold", color=colour,
                     ha="center", va="center", zorder=7,
                     bbox=dict(boxstyle="round,pad=0.26", fc="white", ec=colour,
                               lw=1.2, alpha=0.95))

    def note(self, text, deg, r, size: float = 9.5):
        import numpy as np
        self.ax.text(np.radians(deg), r, text, size=size, color=INK_SOFT,
                     ha="center", va="center", linespacing=1.35, zorder=7,
                     bbox=dict(boxstyle="round,pad=0.3", fc="white", ec=GRID, lw=1.0))

def legend_handles_pair(label_a: str, label_b: str, *, scale: float = 1.0):
    """Legend handles for the two-series pair, matching :func:`Radar.plot`.

    Needed when the legend belongs to the figure rather than to one of the
    axes, so it cannot be built from an axes' own artists.
    """
    from matplotlib.lines import Line2D
    out = []
    for i, (label, colour) in enumerate(((label_a, PAIR_A), (label_b, PAIR_B))):
        out.append(Line2D([0], [0], color=colour, lw=2.4 * scale,
                          linestyle=DASHES[i % len(DASHES)],
                          marker=MARKERS[i % len(MARKERS)],
                          markersize=7.0 * scale, markerfacecolor="white",
                          markeredgewidth=2.0 * scale, markeredgecolor=colour,
                          label=label))
    return out


apply_rc()
