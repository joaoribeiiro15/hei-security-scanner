import logging

# Central configuration dictionary for the DNSSEC scanner pipeline.
# All tuneable parameters should be changed here rather than in individual modules.
_config: dict[str, str | int] = {
    "max_workers": 6,
    "url_base_api": "https://dns.google/resolve",
    "error_column": "error",
    "errors_folder": "errors",
    "results_folder": "results",
    "log_level": logging.INFO,
    "log_format": '%(asctime)s - %(levelname)s - %(message)s',
    "country_column": "country",
    "score_column": "score",
    # FIX (Bug 1): Changed from "ETER_ID" to "ID" to match the column name
    # used in the result CSV files (e.g. no_dnssec_scanner.csv).
    # The consolidation step in get_consolidated_data.py normalises legacy
    # "ETER_ID" columns to "ID" so both old and new result files are supported.
    "id_column": "ID",
}


class Config:
    @staticmethod
    def get_max_workers() -> int:
        return _config.get("max_workers", 5)

    @staticmethod
    def get_url_base_api() -> str:
        return _config.get("url_base_api", "https://dns.google/resolve")

    @staticmethod
    def get_error_column() -> str:
        return _config.get("error_column", "error")

    @staticmethod
    def get_errors_folder() -> str:
        return _config.get("errors_folder", "errors")

    @staticmethod
    def get_results_folder() -> str:
        return _config.get("results_folder", "results")

    @staticmethod
    def get_log_level() -> int:
        return _config.get("log_level", logging.INFO)

    @staticmethod
    def get_log_format() -> str:
        return _config.get("log_format", '%(asctime)s - %(levelname)s - %(message)s')

    @staticmethod
    def get_country_column() -> str:
        return _config.get("country_column", "country")

    @staticmethod
    def get_score_column() -> str:
        return _config.get("score_column", "score")

    @staticmethod
    def get_id_column() -> str:
        return _config.get("id_column", "ID")
