import os
from pathlib import Path

RESULT_FILENAME = 'sh_final_result_with_scores_unique_hei.csv'

# Absolute path to the project root (3 levels up from this file:
# setup.py → report/ → analyzer/ → src/ → project root)
ROOT_DIRECTORY = Path(__file__).resolve().parents[3]

RESULT_FILE_PATH = ROOT_DIRECTORY / 'src' / 'data' / 'results' / 'analysis' / RESULT_FILENAME
RESULT_PLATFORM_FILE_PATH = ROOT_DIRECTORY / 'src' / 'data' / 'results' / 'analysis' / 'sh_final_result_with_scores.csv'
OUTPUT_ANALYSIS_BASE_DIRECTORY = ROOT_DIRECTORY / 'src' / 'data' / 'results' / 'analysis'
TABLE_DIRECTORY = OUTPUT_ANALYSIS_BASE_DIRECTORY / 'tables'
CHART_DIRECTORY = OUTPUT_ANALYSIS_BASE_DIRECTORY / 'charts'

os.makedirs(TABLE_DIRECTORY, exist_ok=True)
os.makedirs(CHART_DIRECTORY, exist_ok=True)
