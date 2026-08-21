from src.scanner.models.DNSSECStatus import DNSSECStatus


def determine_dnssec_status(dnskey_response: dict, dnskey_response_no_validation: dict) -> DNSSECStatus:
    if dnskey_response.get("Status") == 2 and dnskey_response_no_validation.get("Status") == 2:
        return DNSSECStatus.BAD_DELEGATION

    if dnskey_response.get("Status") == 2:
        return DNSSECStatus.INVALID

    if dnskey_response.get("Status") == 0 and not dnskey_response.get("AD"):
        return DNSSECStatus.NONE

    if dnskey_response.get("Status") == 0 and dnskey_response.get("AD"):
        return DNSSECStatus.VALID

    return DNSSECStatus.NONE
