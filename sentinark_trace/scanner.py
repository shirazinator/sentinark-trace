"""
Sentinark-Trace: Unified Scanner Orchestrator
Coordinates redirect tracing, lexical heuristics, DNS resolution, and threat scoring.
"""

from typing import Dict, Any
from .redirect_tracker import trace_redirect_chain
from .heuristics import analyze_url_heuristics
from .domain_intel import resolve_domain_intel
from .threat_scorer import calculate_phishing_threat


def scan_url(target_url: str, trace_hops: bool = True) -> Dict[str, Any]:
    """
    Scans a suspected phishing link safely through the complete threat intelligence pipeline.
    """
    if not target_url.strip():
        return {"error": "Empty URL provided"}

    # 1. Trace Redirection Chain Safely
    if trace_hops:
        redirect_data = trace_redirect_chain(target_url)
    else:
        redirect_data = {
            "initial_url": target_url,
            "final_url": target_url,
            "total_hops": 1,
            "hops": [{"hop": 1, "url": target_url, "status_code": 200}],
            "uses_shortener": False,
            "multiple_redirects": False
        }

    # 2. Run Heuristic Lexical Analysis on Final Destination URL
    final_dest = redirect_data["final_url"]
    heuristic_data = analyze_url_heuristics(final_dest)

    # 3. Resolve Domain Network Intelligence
    domain_data = resolve_domain_intel(heuristic_data["hostname"])

    # 4. Compute Unified Threat Matrix
    threat_dossier = calculate_phishing_threat(redirect_data, heuristic_data, domain_data)

    return {
        "url_scanned": target_url,
        "threat_dossier": threat_dossier,
        "redirect_chain": redirect_data["hops"],
        "heuristic_analysis": heuristic_data
    }
