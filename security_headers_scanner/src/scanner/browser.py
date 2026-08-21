import requests
import urllib3
from src.config import config
from src.scanner.scan_result import ScanResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_REDIRECTS = 10
CONNECT_TIMEOUT = 10  # seconds to establish TCP connection
READ_TIMEOUT = 30     # seconds to wait for response data


def get_scan_result(url, user_agent, language):
    headers = {
        "User-Agent": user_agent,
        "Accept-Language": language,
    }

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    try:
        response = session.get(
            url,
            headers=headers,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,
            allow_redirects=True,
        )

        if response.history:
            initial_status = response.history[0].status_code
            redirect_count = len(response.history)
        else:
            initial_status = response.status_code
            redirect_count = 0

        protocol = "h2" if response.raw.version == 20 else "http/1.1"

        return ScanResult(
            initial_status=initial_status,
            final_status=response.status_code,
            redirect_count=redirect_count,
            headers=dict(response.headers),
            protocol=protocol,
            final_url=response.url,
        )

    except requests.exceptions.TooManyRedirects as e:
        raise RuntimeError(f"Too many redirects: {e}")
    except requests.exceptions.SSLError as e:
        raise RuntimeError(f"SSL error: {e}")
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Connection error: {e}")
    except requests.exceptions.Timeout as e:
        raise RuntimeError(f"Timeout: {e}")
