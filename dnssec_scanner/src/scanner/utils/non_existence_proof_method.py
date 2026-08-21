from src.scanner.models.NonExistenceProofMethod import NonExistenceProofMethod


def determine_non_existence_proof_method(nsec_response: dict, nsec3param_response: dict) -> NonExistenceProofMethod:
    nsec_in_use: bool = (
            nsec_response.get("Status") == 0 and
            nsec_response.get("Answer") and
            nsec_response["Answer"][0].get("type") == 47
    )
    nsec3param_in_use: bool = (
            nsec3param_response.get("Status") == 0 and
            nsec3param_response.get("Answer") and
            nsec3param_response["Answer"][0].get("type") == 51
    )

    if nsec_in_use and not nsec3param_in_use:
        return NonExistenceProofMethod.NSEC

    if not nsec_in_use and nsec3param_in_use:
        return NonExistenceProofMethod.NSEC3

    if nsec_in_use and nsec3param_in_use:
        return NonExistenceProofMethod.INVALID

    return NonExistenceProofMethod.NONE
