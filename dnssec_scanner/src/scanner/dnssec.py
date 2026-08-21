import json
import logging
from dataclasses import asdict
from threading import Lock
import pandas as pd
from concurrent.futures.thread import ThreadPoolExecutor

from src.config.config import Config
from src.scanner.models.Algorithm import Algorithm
from src.scanner.models.DNSSECResult import DNSSECResult
from src.scanner.models.DNSSECStatus import DNSSECStatus
from src.scanner.models.DigestAlgorithm import DigestAlgorithm
from src.scanner.models.NonExistenceProofMethod import NonExistenceProofMethod
from src.scanner.models.csv_data_info import CsvDataInfo
from src.scanner.models.grade import Grade
from src.scanner.models.rating import Rating
from src.scanner.utils.calculateScore import calculate_score_default
from src.scanner.utils.determine_dnssec_status import determine_dnssec_status
from src.scanner.utils.dnssec_query import dnssec_query
from src.scanner.utils.extract_domain import extract_domain
from src.scanner.utils.load_csv_data import load_csv_data
from src.scanner.utils.non_existence_proof_method import determine_non_existence_proof_method
from src.scanner.utils.parse_dnskey_data import parse_dnskey_data
from src.scanner.utils.parse_ds_data import parse_ds_data
from src.scanner.utils.saveResults import save_results

final_errors: list[dict[str, any]] = []
final_results: list[dict[str, any]] = []
lock: Lock = Lock()


def scan(file_path: str):
    global final_errors
    global final_results
    final_errors = []
    final_results = []

    csv_data_info: CsvDataInfo = load_csv_data(file_path)

    with ThreadPoolExecutor(max_workers=Config.get_max_workers()) as executor:
        futures: list = [executor.submit(scan_row, row, csv_data_info.url_column) for index, row in
                         csv_data_info.dataframe.iterrows()]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logging.error(f"Thread error in CSV ({csv_data_info.filename}): {e}")

    if final_results:
        save_results(final_results, csv_data_info.country_code)
    if final_errors:
        save_results(final_errors, csv_data_info.country_code, error=True)


def scan_row(row: pd.Series, url_column: str):
    global final_errors
    global final_results
    try:
        domain_to_scan: str = extract_domain(row[url_column])
        logging.info(f"Scanning domain: {domain_to_scan}")
        dnskey_response: dict = dnssec_query(domain_to_scan, "DNSKEY")
        dnskey_response_no_validation: dict = dnssec_query(domain_to_scan, "DNSKEY", disable_dnssec_validation=True)
        dnssec_status: DNSSECStatus = determine_dnssec_status(dnskey_response, dnskey_response_no_validation)
        raw_result: dict[str, dict] = {
            "dnskey": dnskey_response,
            "dnskeyNoValidation": dnskey_response_no_validation,
        }
        algorithms: list[Algorithm] = []
        digest_algorithms: list[DigestAlgorithm] = []
        non_existence_proof_method: NonExistenceProofMethod = NonExistenceProofMethod.NONE
        if dnssec_status == DNSSECStatus.VALID:
            answers = dnskey_response.get("Answer", [])
            algorithms = [parse_dnskey_data(record.get("data", "")) for record in answers]

            ds_response: dict = dnssec_query(domain_to_scan, "DS")
            raw_result.update({"ds": ds_response})
            ds_answers = ds_response.get("Answer", [])
            digest_algorithms = [parse_ds_data(record.get("data", "")) for record in ds_answers]

            nsec_response: dict = dnssec_query(domain_to_scan, "NSEC")
            raw_result.update({"nsec": nsec_response})
            nsec3param_response: dict = dnssec_query(domain_to_scan, "NSEC3PARAM")
            raw_result.update({"nsec3Param": nsec3param_response})
            non_existence_proof_method = determine_non_existence_proof_method(nsec_response, nsec3param_response)
        result: DNSSECResult = DNSSECResult(
            assessment_datetime=pd.Timestamp.now(),
            dnssec_status=dnssec_status,
            non_existence_proof_method=non_existence_proof_method,
            score=0,
            grade=Grade.F,
            algorithms=algorithms,
            digest_algorithms=digest_algorithms,
            raw_result=json.dumps(raw_result),
        )
        rating: Rating = calculate_score_default(result)
        result.score = rating.score
        result.grade = rating.grade
        with lock:
            final_results.append({**row.to_dict(), **asdict(result)})
    except Exception as e:
        logging.error(f"Error scanning URL {row[url_column]}: {e}")
        with lock:
            final_errors.append({**row.to_dict(), Config.get_error_column(): str(e)})
