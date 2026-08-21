from src.scanner.models.AlgorithmRecommendation import AlgorithmRecommendation
from src.scanner.models.AlgorithmRecommendationMap import AlgorithmRecommendationMap
from src.scanner.models.RFCRecommendation import RFCRecommendation


def get_dnssec_digest_algorithms_recommendations_map() -> AlgorithmRecommendationMap:

    return {
        0: AlgorithmRecommendation(name="NULL (CDS only)", classificationRFC8624=RFCRecommendation.MUST_NOT),
        1: AlgorithmRecommendation(name="SHA1", classificationRFC8624=RFCRecommendation.MUST_NOT),
        2: AlgorithmRecommendation(name="SHA256", classificationRFC8624=RFCRecommendation.MUST),
        3: AlgorithmRecommendation(name="GOST R 34.11-94", classificationRFC8624=RFCRecommendation.MUST_NOT),
        4: AlgorithmRecommendation(name="SHA384", classificationRFC8624=RFCRecommendation.MAY),
    }



