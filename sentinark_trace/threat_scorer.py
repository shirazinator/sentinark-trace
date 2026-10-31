"""
Sentinark-Trace: Unified Phishing Threat Scorer & Forensic Dossier
Combines redirect chains, lexical heuristics, and domain network intelligence.
"""

from typing import Dict, Any


def calculate_phishing_threat(
    redirect_info: Dict[str, Any],
    heuristic_info: Dict[str, Any],
    domain_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes unified threat score (0 - 100) and forensic classification.
    """
    score = float(heuristic_info["penalty_score"])

    # Boost score if URL redirects to an entirely different root domain
    if redirect_info["multiple_redirects"]:
        score += 15.0

    if redirect_info["uses_shortener"]:
        score += 10.0

    # Cap score at 100
    final_score = min(round(score, 1), 100.0)

    # Classify Risk Tier
    if final_score >= 75.0:
        tier = "CRITICAL: High-Risk Phishing / Malicious Vector"
        action = "DO NOT VISIT. Block domain across network firewalls and report to Google Safe Browsing."
    elif final_score >= 45.0:
        tier = "HIGH: Deceptive Credential Lure / Suspicious Cloak"
        action = "Exercise extreme caution. Inspect final redirect destination in sandbox."
    elif final_score >= 20.0:
        tier = "MEDIUM: Low-Trust or Obfuscated Link"
        action = "Verify sender authenticity before entering sensitive credentials."
    else:
        tier = "BENIGN: Standard Web Link"
        action = "No malicious indicators detected."

    return {
        "threat_score": final_score,
        "risk_tier": tier,
        "recommended_action": action,
        "redirect_summary": {
            "initial": redirect_info["initial_url"],
            "final": redirect_info["final_url"],
            "hops_count": redirect_info["total_hops"],
            "shortener_used": redirect_info["uses_shortener"]
        },
        "flags": heuristic_info["flags"],
        "domain_intel": domain_info
    }
