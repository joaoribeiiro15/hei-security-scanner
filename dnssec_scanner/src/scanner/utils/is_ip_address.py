import re


def is_ip_address(hostname: str) -> bool:
    octet = r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ipv4_regex = re.compile(r'^' + octet + r'\.' + octet + r'\.' + octet + r'\.' + octet + r'$')
    ipv6_regex = re.compile(r'^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$')

    return bool(ipv4_regex.match(hostname)) or bool(ipv6_regex.match(hostname))
