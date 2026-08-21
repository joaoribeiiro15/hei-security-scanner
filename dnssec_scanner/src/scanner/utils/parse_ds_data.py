import logging

from src.scanner.models.AlgorithmRecommendation import AlgorithmRecommendation
from src.scanner.models.DigestAlgorithm import DigestAlgorithm
from src.scanner.utils.get_dnssec_digest_algorithm_info import get_dnssec_digest_algorithm_info


def parse_ds_data(ds_data: str) -> DigestAlgorithm:
    parts: list[str] = ds_data.split(" ")  # [keyTag, algorithm, digestType, digest]
    try:
        digest_code: int = int(parts[2])
    except ValueError:
        logging.error(f"Invalid digest code: {parts}")
        digest_code: int = -1

    digest_info: AlgorithmRecommendation = get_dnssec_digest_algorithm_info(digest_code)

    return DigestAlgorithm(
        digest_code,
        digest_info.name,
        digest_info.classificationRFC8624,
    )
