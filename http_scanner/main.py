import argparse
import logging
import os

from src.scanner.http import scan
from src.analyzer.main import main as run_analysis


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

    parser = argparse.ArgumentParser(description="HTTP/TLS scanner and analyzer")
    parser.add_argument("--https", action="store_true", help="Run HTTPS/TLS analysis")
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="Skip scanning; re-derive cert columns from stored raw JSON and regenerate reports",
    )
    args = parser.parse_args()

    if args.analyze_only:
        logging.info("Analyze-only mode: re-deriving cert columns and running analysis.")
        run_analysis(rederive=True)
        logging.info("Analysis complete.")
        return

    input_directory = os.path.join('.', 'src', 'data', 'source')
    files = [f for f in os.listdir(input_directory) if f.endswith('.csv')]
    logging.info(f"Found {len(files)} files to scan.")

    if not files:
        logging.warning(
            f"No CSV files found in '{input_directory}'. "
            f"Please ensure the files are in the correct directory."
        )
        return

    for file in files:
        file_path = os.path.join(input_directory, file)
        try:
            scan(file_path)
        except Exception as e:
            logging.error(f"Error scanning {file}: {e}")

    logging.info("Scan complete. Starting analysis...")
    try:
        run_analysis()
        logging.info("Analysis complete.")
    except Exception as e:
        logging.error(f"Error during analysis: {e}")


if __name__ == "__main__":
    main()
