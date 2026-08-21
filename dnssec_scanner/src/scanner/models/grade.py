from enum import Enum


class Grade(Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value
