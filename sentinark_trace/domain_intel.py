"""
Sentinark-Trace: Domain Intelligence & Network Host Resolver
Resolves DNS A records and retrieves network host indicators safely.
"""

import socket
from typing import Dict, Any, List


def resolve_domain_intel(hostname: str) -> Dict[str, Any]:
    """
    Resolves domain DNS records and IP details safely using socket.
    """
    clean_host = hostname.split(":")[0].strip()
    resolved_ips: List[str] = []

    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        for item in addr_info:
            ip = item[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
        dns_status = "RESOLVED"
    except socket.gaierror:
        dns_status = "NXDOMAIN_OR_UNRESOLVABLE"
    except Exception as e:
        dns_status = f"ERROR: {str(e)}"

    return {
        "hostname": clean_host,
        "dns_status": dns_status,
        "resolved_ips": resolved_ips[:5],
        "is_active_domain": len(resolved_ips) > 0
    }
