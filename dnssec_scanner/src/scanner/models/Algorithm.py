from dataclasses import dataclass

from src.scanner.models.DNSKeyType import DNSKeyType
from src.scanner.models.RFCRecommendation import RFCRecommendation


@dataclass
class Algorithm:
    code: int
    name: str
    classificationRFC8624: RFCRecommendation
    dnsKeyType: DNSKeyType
