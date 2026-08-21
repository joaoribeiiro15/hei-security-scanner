from typing import NamedTuple

from src.scanner.models.RFCRecommendation import RFCRecommendation


class AlgorithmRecommendation(NamedTuple):
    name: str
    classificationRFC8624: RFCRecommendation