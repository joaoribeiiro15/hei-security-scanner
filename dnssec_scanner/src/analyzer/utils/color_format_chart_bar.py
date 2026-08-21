from matplotlib.axes import Axes


def format_bar_annotations(ax: Axes):
    for container in ax.containers:
        for rect, value in zip(container, container.datavalues):
            if value > 0:
                height = rect.get_height()
                width = rect.get_width()
                x_pos = rect.get_x() + width / 2
                y_pos = rect.get_y() + height / 2 - 0.05

                if width > 3:
                    face_color = rect.get_facecolor()[:3]
                    brightness: int = sum([c * w for c, w in zip(face_color, [0.299, 0.587, 0.114])])
                    text_color: str = "black" if brightness > 0.5 else "white"
                    ax.text(x_pos, y_pos, f"{value:.1f}", ha="center", va="center",
                            fontsize=10, color=text_color)
