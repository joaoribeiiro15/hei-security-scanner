from dataclasses import dataclass

from src.scanner.models.RFCRecommendation import RFCRecommendation


@dataclass
class DigestAlgorithm:
    code: int
    name: str
    classificationRFC8624: RFCRecommendation