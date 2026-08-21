from src.scanner.models.AlgorithmRecommendationMap import AlgorithmRecommendationMap
from src.scanner.models.DNSSECResult import DNSSECResult
from src.scanner.models.DNSSECStatus import DNSSECStatus
from src.scanner.models.NonExistenceProofMethod import NonExistenceProofMethod
from src.scanner.models.RFCRecommendation import RFCRecommendation
from src.scanner.models.grade import Grade
from src.scanner.models.rating import Rating
from src.scanner.utils.get_dnssec_algorithms_recomendation_map import get_dnssec_algorithms_recommendation_map
from src.scanner.utils.get_dnssec_digest_algorithms import get_dnssec_digest_algorithms_recommendations_map


def calculate_score_default(partial_result: DNSSECResult) -> Rating:
    dnssec_algorithms: AlgorithmRecommendationMap = get_dnssec_algorithms_recommendation_map()
    dnssec_digest_algorithms: AlgorithmRecommendationMap = get_dnssec_digest_algorithms_recommendations_map()

    status_score: float = 100 if partial_result.dnssec_status == DNSSECStatus.VALID else 0

    signing_alg_score: RFCRecommendation = RFCRecommendation.MUST
    digest_alg_score: RFCRecommendation = RFCRecommendation.MUST
    proof_method_score = 0

    if partial_result.non_existence_proof_method == NonExistenceProofMethod.NSEC:
        proof_method_score = 100
    elif partial_result.non_existence_proof_method == NonExistenceProofMethod.NSEC3:
        proof_method_score = 90
    elif partial_result.non_existence_proof_method == NonExistenceProofMethod.INVALID:
        proof_method_score = 30
    elif partial_result.non_existence_proof_method == NonExistenceProofMethod.NONE:
        proof_method_score = 0

    if not partial_result.algorithms:
        signing_alg_score = RFCRecommendation.MUST_NOT
    else:
        for algorithm in partial_result.algorithms:
            rec = dnssec_algorithms.get(algorithm.code)
            score = rec.classificationRFC8624 if rec is not None else RFCRecommendation.MUST_NOT
            if score < signing_alg_score:
                signing_alg_score = score

    if not partial_result.digest_algorithms:
        digest_alg_score = RFCRecommendation.MUST_NOT
    else:
        for algorithm in partial_result.digest_algorithms:
            rec = dnssec_digest_algorithms.get(algorithm.code)
            score = rec.classificationRFC8624 if rec is not None else RFCRecommendation.MUST_NOT
            if score < digest_alg_score:
                digest_alg_score = score

    signing_alg_weighted_score: float = (signing_alg_score / RFCRecommendation.MUST.value) * 100
    digest_alg_weighted_score: float = (digest_alg_score / RFCRecommendation.MUST.value) * 100

    # Paper Table I weights: Status 50%, Signature Alg 30%, Digest Alg 15%, NSEC Method 5%
    final_score: float = round(
        (status_score * 0.50) +
        (signing_alg_weighted_score * 0.30) +
        (digest_alg_weighted_score * 0.15) +
        (proof_method_score * 0.05),
        2
    )

    # Thresholds aligned with the scoring framework in the paper:
    # A [80-100], B [65-79], C [50-64], D [35-49], E [20-34], F [0-19]
    if final_score >= 80:
        grade = Grade.A
    elif final_score >= 65:
        grade = Grade.B
    elif final_score >= 50:
        grade = Grade.C
    elif final_score >= 35:
        grade = Grade.D
    elif final_score >= 20:
        grade = Grade.E
    else:
        grade = Grade.F

    return Rating(final_score, grade)
