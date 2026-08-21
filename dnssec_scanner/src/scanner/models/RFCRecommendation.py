from enum import IntEnum


class RFCRecommendation(IntEnum):
    MUST_NOT = 0
    NOT_RECOMMENDED = 25
    MAY = 50
    RECOMMENDED = 75
    MUST = 100

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)