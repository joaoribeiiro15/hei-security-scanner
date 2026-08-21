from enum import Enum


class DNSKeyType(Enum):
    KSK = "Key Signing Key (KSK)"
    ZSK = "Zone Signing Key (ZSK)"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value