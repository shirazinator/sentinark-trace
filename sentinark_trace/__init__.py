"""
Sentinark-Trace: Automated Phishing & Redirection Threat Intelligence Scanner
"""

__version__ = "1.0.0"
__author__ = "Shiraz"

from .scanner import scan_url
from .redirect_tracker import trace_redirect_chain
from .heuristics import analyze_url_heuristics
from .domain_intel import resolve_domain_intel
from .threat_scorer import calculate_phishing_threat

__all__ = [
    "scan_url",
    "trace_redirect_chain",
    "analyze_url_heuristics",
    "resolve_domain_intel",
    "calculate_phishing_threat"
]
