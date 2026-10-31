"""
Sentinark-Trace: Lexical & Heuristic Phishing Risk Analyzer
Detects URL homographs, deceptive subdomains, suspicious TLDs, and credential lures.
"""

import re
import urllib.parse
from typing import Dict, List, Any

HIGH_RISK_TLDS = {
    "xyz", "top", "click", "buzz", "club", "work", "gq", "cf", "ml", "tk",
    "ga", "country", "live", "link", "stream", "review", "account", "vip"
}

TARGETED_BRANDS = [
    "instagram", "facebook", "meta", "whatsapp", "google", "apple", "microsoft",
    "paypal", "netflix", "amazon", "binance", "coinbase", "chase", "wellsfargo"
]

CREDENTIAL_HARVEST_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "update",
    "confirm", "account", "recover", "recovery", "appeal", "password", "auth",
    "authenticate", "banking", "wallet", "suspend", "suspended", "notice"
]


def analyze_url_heuristics(url_str: str) -> Dict[str, Any]:
    """
    Performs comprehensive lexical security analysis on a given URL.
    """
    flags: List[str] = []
    penalty_score = 0

    parsed = urllib.parse.urlparse(url_str)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url_str.lower()

    # Strip port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    # 1. IP Address as Hostname Check (e.g. http://192.168.1.1/login)
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, hostname):
        flags.append("Raw IP address used as hostname instead of a registered domain")
        penalty_score += 40

    # 2. Punycode / IDN Homograph Attack (e.g., xn--...)
    if "xn--" in hostname:
        flags.append("Punycode (IDN) detected: Hostname uses foreign character encoding to spoof legitimate brand characters")
        penalty_score += 45

    # 3. HTTP Basic Auth / URL Deception with '@' (e.g. http://google.com@attacker.com)
    if "@" in parsed.netloc:
        flags.append("Deceptive '@' symbol in authority section: Attempt to trick user on true destination")
        penalty_score += 50

    # 4. High-Risk / Abused TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        flags.append(f"High-risk Top-Level Domain (TLD): '.{tld}' is heavily correlated with malicious campaigns")
        penalty_score += 25

    # 5. Excessive Subdomain Depth (e.g., sub1.sub2.sub3.domain.com)
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) >= 4:
        flags.append(f"Excessive subdomain nesting ({len(subdomain_parts)} parts): Common tactic to obscure actual domain")
        penalty_score += 20

    # 6. Brand Spoofing / Deceptive Brand Usage
    # Check if a brand name appears in subdomains or path when the root domain is NOT that brand
    root_domain = ".".join(subdomain_parts[-2:]) if len(subdomain_parts) >= 2 else hostname
    for brand in TARGETED_BRANDS:
        if brand in hostname or brand in path:
            # If the brand is not the root domain itself (e.g., 'instagram.com.attacker.xyz')
            if not root_domain.startswith(brand + "."):
                flags.append(f"Deceptive Brand Spoofing: Contains '{brand}' in URL, but true root domain is '{root_domain}'")
                penalty_score += 45
                break

    # 7. Credential Harvesting Lure Keywords
    found_keywords = [kw for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in full_url]
    if found_keywords:
        flags.append(f"Contains credential harvesting lure terms: {', '.join(found_keywords[:4])}")
        penalty_score += min(len(found_keywords) * 12, 35)

    # 8. Suspicious URL Length (> 85 characters)
    if len(url_str) > 85:
        flags.append(f"Abnormally long URL ({len(url_str)} chars): Often used to hide malicious tokens or deceive mobile browser viewports")
        penalty_score += 15

    # 9. Insecure Protocol
    if parsed.scheme == "http":
        flags.append("Cleartext HTTP Protocol (Missing TLS/SSL encryption)")
        penalty_score += 10

    return {
        "hostname": hostname,
        "root_domain": root_domain,
        "tld": tld,
        "penalty_score": min(penalty_score, 100),
        "flags": flags,
        "is_suspicious": len(flags) > 0
    }
