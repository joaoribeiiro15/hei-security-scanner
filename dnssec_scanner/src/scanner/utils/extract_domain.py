import re
from urllib.parse import urlparse

from src.scanner.utils.is_ip_address import is_ip_address


def extract_domain(url: str) -> str:
    try:
        normalized_url: str = re.sub(r'\s+', '', url)

        if not re.match(r'^https?://', normalized_url, re.IGNORECASE):
            normalized_url = f"https://{normalized_url}"

        parsed_url = urlparse(normalized_url)
        hostname = parsed_url.hostname

        if hostname is None:
            raise ValueError(f"Hostname not found in URL: {url}")

        if is_ip_address(hostname):
            raise ValueError(f"Hostname is an IP address: {url}")

        hostname = hostname.encode('idna').decode('ascii')

        parts = hostname.split('.')[::-1]

        if len(parts) >= 2:
            return parts[1] + '.' + parts[0]

        return hostname
    except Exception as e:
        raise ValueError(f"Invalid URL: {url} to extract domain. Error: {e}")
