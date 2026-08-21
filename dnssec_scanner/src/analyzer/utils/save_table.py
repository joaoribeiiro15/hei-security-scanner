from src.analyzer.utils.save_text_file import save
from src.config.paths import TABLE_DIRECTORY


def save_table(table: str, filename: str):
    save(table, filename, TABLE_DIRECTORY)
