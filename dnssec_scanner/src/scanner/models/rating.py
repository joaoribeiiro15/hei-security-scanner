from dataclasses import dataclass

from src.scanner.models.grade import Grade


@dataclass
class Rating:
    score: float
    grade: Grade



