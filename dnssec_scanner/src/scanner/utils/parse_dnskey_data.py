import logging

from src.scanner.models.Algorithm import Algorithm
from src.scanner.models.AlgorithmRecommendation import AlgorithmRecommendation
from src.scanner.models.DNSKeyType import DNSKeyType
from src.scanner.utils.get_dnssec_algorithm_info import get_dnssec_algorithm_info


def parse_dnskey_data(dns_key_data: str) -> Algorithm:
    parts: list[str] = dns_key_data.split(" ")
    try:
        flags = parts[0]
        algorithm = parts[2]
        algorithm_code = int(algorithm)
    except ValueError:
        logging.error(f"Invalid DNSKEY data: {parts}")
        algorithm_code = -1
        flags = "-1"

    algorithm_info: AlgorithmRecommendation = get_dnssec_algorithm_info(algorithm_code)
    dns_key_type: DNSKeyType = "-1" if flags == "-1" else DNSKeyType.KSK if flags == "257" else DNSKeyType.ZSK

    return Algorithm(
        dnsKeyType=dns_key_type,
        code=algorithm_code,
        name=algorithm_info.name,
        classificationRFC8624=algorithm_info.classificationRFC8624,
    )
