from src.scanner.models.AlgorithmRecommendation import AlgorithmRecommendation
from src.scanner.models.AlgorithmRecommendationMap import AlgorithmRecommendationMap
from src.scanner.utils.get_dnssec_digest_algorithms import get_dnssec_digest_algorithms_recommendations_map


def get_dnssec_digest_algorithm_info(digest_code: int) -> AlgorithmRecommendation:
    digest_algorithms_map: AlgorithmRecommendationMap = get_dnssec_digest_algorithms_recommendations_map()
    return digest_algorithms_map.get(digest_code, {
        "name": "Unknown",
        "classificationRFC8624": "Unknown"
    })
