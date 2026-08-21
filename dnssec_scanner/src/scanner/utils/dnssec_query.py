import logging

import requests
from requests import Response

from src.config.config import Config


def dnssec_query(domain: str, record_type: str, disable_dnssec_validation: bool = False) -> dict:
    cd: str = 'true' if disable_dnssec_validation else 'false'
    url: str = f"{Config.get_url_base_api()}?name={domain.strip()}&type={record_type.strip()}&cd={cd}"

    logging.debug(f"Querying DNSSEC API: {url}")
    response: Response = requests.get(url)

    if response.status_code != 200:
        raise Exception(f"Network response error: {response.reason}")

    return response.json()
