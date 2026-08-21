from src.scanner.models.AlgorithmRecommendation import AlgorithmRecommendation
from src.scanner.models.AlgorithmRecommendationMap import AlgorithmRecommendationMap
from src.scanner.models.RFCRecommendation import RFCRecommendation


def get_dnssec_algorithms_recommendation_map() -> AlgorithmRecommendationMap:
    return {
        1: AlgorithmRecommendation(name="RSAMD5", classificationRFC8624=RFCRecommendation.MUST_NOT),
        3: AlgorithmRecommendation(name="DSA", classificationRFC8624=RFCRecommendation.MUST_NOT),
        5: AlgorithmRecommendation(name="RSASHA1", classificationRFC8624=RFCRecommendation.NOT_RECOMMENDED),
        6: AlgorithmRecommendation(name="DSA-NSEC3-SHA1", classificationRFC8624=RFCRecommendation.MUST_NOT),
        7: AlgorithmRecommendation(name="RSASHA1-NSEC3-SHA1", classificationRFC8624=RFCRecommendation.NOT_RECOMMENDED),
        8: AlgorithmRecommendation(name="RSASHA256", classificationRFC8624=RFCRecommendation.MUST),
        10: AlgorithmRecommendation(name="RSASHA512", classificationRFC8624=RFCRecommendation.NOT_RECOMMENDED),
        12: AlgorithmRecommendation(name="ECC-GOST", classificationRFC8624=RFCRecommendation.MUST_NOT),
        13: AlgorithmRecommendation(name="ECDSAP256SHA256", classificationRFC8624=RFCRecommendation.MUST),
        14: AlgorithmRecommendation(name="ECDSAP384SHA384", classificationRFC8624=RFCRecommendation.MAY),
        15: AlgorithmRecommendation(name="ED25519", classificationRFC8624=RFCRecommendation.RECOMMENDED),
        16: AlgorithmRecommendation(name="ED448", classificationRFC8624=RFCRecommendation.MAY),
    }
