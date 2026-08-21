from src.scanner.models.AlgorithmRecommendation import AlgorithmRecommendation
from src.scanner.models.AlgorithmRecommendationMap import AlgorithmRecommendationMap
from src.scanner.utils.get_dnssec_algorithms_recomendation_map import get_dnssec_algorithms_recommendation_map


def get_dnssec_algorithm_info(algorithm_code: int) -> AlgorithmRecommendation:
    algorithms_map: AlgorithmRecommendationMap = get_dnssec_algorithms_recommendation_map()
    return algorithms_map.get(algorithm_code, {
        "name": "Unknown",
        "classificationRFC8624": "Unknown"
    })
