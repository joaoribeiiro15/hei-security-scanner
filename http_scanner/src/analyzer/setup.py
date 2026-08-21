import os
from pathlib import Path

# Resolve the project root from this file's location:
# setup.py is at src/analyzer/setup.py, so parents[2] is the project root.
ROOT_DIRECTORY = str(Path(__file__).resolve().parents[2])
DATA_SOURCE_DIRECTORY = os.path.join(ROOT_DIRECTORY, 'src', 'data', 'results')
ANALYSIS_BASE_DIRECTORY = os.path.join(ROOT_DIRECTORY, 'src', 'data', 'reports')
FILE_TO_ANALYZE = os.path.join(ANALYSIS_BASE_DIRECTORY, 'https_consolidate_result.csv')
TABLE_DIRECTORY = os.path.join(ANALYSIS_BASE_DIRECTORY, 'tables')
CHART_DIRECTORY = os.path.join(ANALYSIS_BASE_DIRECTORY, 'charts')


def setup():
    os.makedirs(TABLE_DIRECTORY, exist_ok=True)
    os.makedirs(CHART_DIRECTORY, exist_ok=True)
