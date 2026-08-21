import logging
import sys

from src.config.config import Config
from src.config.paths import LOG_FILE


def logging_setup():
    logging.basicConfig(
        level=Config.get_log_level(),
        format=Config.get_log_format(),
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )
