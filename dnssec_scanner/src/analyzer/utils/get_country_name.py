
def get_country_name(country_code: str) -> str:
    mapping = {
        "de": "Germany",
        "fr": "France",
        "it": "Italy",
        "no": "Norway",
        "pt": "Portugal",
        "es": "Spain",
        "se": "Sweden",
        "dk": "Denmark",
        "fi": "Finland",
        "nl": "Netherlands",
        "be": "Belgium",
        "at": "Austria",
        "ch": "Switzerland",
        "pl": "Poland",
        "cz": "Czech Republic",
        "hu": "Hungary",
        "ro": "Romania",
        "gr": "Greece",
    }
    return mapping.get(country_code.lower(), country_code.upper())