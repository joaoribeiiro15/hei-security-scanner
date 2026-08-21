from enum import Enum


class DNSSECStatus(Enum):
    BAD_DELEGATION = "Bad Delegation"
    INVALID = "Invalid"
    NONE = "Missing"
    VALID = "Valid"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value