from src.analyzer.utils.save_text_file import save
from src.config.paths import CHART_DIRECTORY


def save_chart(table: str, filename: str):
    save(table, filename, CHART_DIRECTORY)
