"""
Sentinark-Trace: Terminal CLI Interface
Run via: python3 -m sentinark_trace.cli
"""

import sys
import argparse
from .scanner import scan_url

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"""{CYAN}{BOLD}
""" + r"""   ____             __  _                  __     ______                    
  / __/___ ___  __ / /_(_)__  ___ ________/ /__  /_  __/______ _________ ___
 _\ \/ -_) _ \/ // / __/ / _ \/ _ `/ __/ _  / _ `/  / / / __/ _ `/ __/ -_)_-<
/___/\__/_//_/\_,_/\__/_/_//_/\_,_/_/  \_,_/\_,_/  /_/ /_/  \_,_/\__/\__/___/ 
     Automated Phishing & Redirection Threat Intelligence Scanner""" + f"""
{RESET}""")


def main():
    parser = argparse.ArgumentParser(description="Sentinark-Trace: Malicious Link & Redirection Scanner")
    parser.add_argument("url", help="Suspicious URL to analyze (e.g. bit.ly/xyz or http://verify-insta.top/login)")
    parser.add_argument("--no-redirect", action="store_true", help="Skip following HTTP redirection chain")

    args = parser.parse_args()
    print_banner()

    print(f"{CYAN}[*] Dissecting target URL: {args.url}{RESET}\n")
    report = scan_url(args.url, trace_hops=not args.no_redirect)

    dossier = report["threat_dossier"]
    score = dossier["threat_score"]
    score_color = RED if score >= 75 else (YELLOW if score >= 40 else GREEN)

    print(f"{BOLD}================ THREAT DOSSIER ================{RESET}")
    print(f"Phishing Threat Score: {score_color}{BOLD}{score} / 100{RESET}")
    print(f"Risk Classification:   {score_color}{BOLD}{dossier['risk_tier']}{RESET}")
    print(f"Recommended Action:    {dossier['recommended_action']}\n")

    # Redirection Chain
    print(f"{BOLD}--- Redirection Chain ({dossier['redirect_summary']['hops_count']} hops) ---{RESET}")
    for hop in report["redirect_chain"]:
        code_str = f"[{hop.get('status_code', 'OK')}]"
        print(f" • Hop {hop['hop']}: {code_str:<8} -> {CYAN}{hop['url']}{RESET}")

    # Heuristic Flags
    print(f"\n{BOLD}--- Security Heuristic Flags ---{RESET}")
    if dossier["flags"]:
        for flag in dossier["flags"]:
            print(f" {RED}[!]{RESET} {flag}")
    else:
        print(f" {GREEN}[✓] Zero malicious lexical patterns discovered.{RESET}")

    # Domain Intel
    intel = dossier["domain_intel"]
    print(f"\n{BOLD}--- Domain Host Intelligence ---{RESET}")
    print(f" • Hostname:    {intel['hostname']}")
    print(f" • DNS Status:  {intel['dns_status']}")
    print(f" • Active IPs:  {', '.join(intel['resolved_ips']) or 'Unresolved / Blocked'}")
    print(f"{BOLD}================================================{RESET}\n")


if __name__ == "__main__":
    main()
