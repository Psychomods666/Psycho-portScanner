COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    3000: "Node.js",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/HTTP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def get_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "Unknown")


def get_risk(port: int, service: str) -> str:
    """
    This is a simple exposure indicator, NOT a vulnerability detector.
    An open port does not automatically mean a system is vulnerable.
    """

    high_exposure = {
        21,
        23,
        445,
        1433,
        1521,
        2375,
        3306,
        3389,
        5432,
        6379,
        9200,
        27017,
    }

    medium_exposure = {
        22,
        25,
        110,
        139,
        161,
        389,
        5900,
        8080,
        8443,
    }

    if port in high_exposure:
        return "HIGH"

    if port in medium_exposure:
        return "MEDIUM"

    return "LOW"