from enum import Enum


class NonExistenceProofMethod(Enum):
    NSEC = "NSEC"
    NSEC3 = "NSEC3"
    INVALID = "Invalid"
    NONE = "Missing"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value