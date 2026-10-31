# 🎯 Sentinark-Trace
### *Automated Phishing, Redirection Chain & Malicious URL Threat Intelligence Scanner*
**Part of the Sentinark Cybersecurity Suite**  
*Authored by Shiraz*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![ThreatIntel](https://img.shields.io/badge/Intel-Phishing%20%26%20Malware%20Defense-teal)](https://github.com/shirazinator)
[![Sandbox](https://img.shields.io/badge/Crawler-Safe%20HTTP%20Sandbox-green)](https://en.wikipedia.org/wiki/Sandbox_(computer_security))
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen?logo=github)](https://shirazinator.github.io/sentinark-trace/)

> **🌐 Live Web Application (Zero-Installation):** [https://shirazinator.github.io/sentinark-trace/](https://shirazinator.github.io/sentinark-trace/)

---

## 📌 Overview

**Sentinark-Trace** is a threat intelligence tool designed to dissect suspicious URLs, unmask obfuscated multi-hop redirection chains, detect homograph attacks and brand impersonation, and evaluate overall phishing probability before a user clicks.

Attackers frequently hide malicious credential-harvesting landing pages behind URL shorteners (like `bit.ly` or `t.co`) or deceptive subdomains (like `instagram.com.account-update.xyz`). Sentinark-Trace acts as a safe, isolated network reconnaissance probe that inspects redirection headers without executing malicious JavaScript or downloading untrusted payloads.

```
+-------------------------------------------------------------------------+
|                           SENTINARK-TRACE                               |
|                  Malicious URL Inspection Pipeline                      |
+-------------------------------------------------------------------------+
       |
       v
 [Suspect URL / Shortener]
       |
       +---> [Safe Intercepting Crawler] ---> Unmasks Hop 1 -> Hop 2 -> Hop N
       |                                      (Captures HTTP Status & Headers)
       |
       +---> [Lexical & Heuristic Scanner] -> Punycode (IDN) / IP-in-URL / High-Risk TLDs
       |                                      Deceptive Subdomains & Credential Lures
       |
       +---> [Network Host Intelligence] ---> DNS A-Record & Host Verification
       |
       +---> [Phishing Threat Index] -------> Unified Risk Classification (0-100%)
```

---

## ✨ Key Features

1. **Safe Multi-Hop Redirection Tracker:**
   - Follows HTTP 301, 302, 303, 307, and 308 redirect loops step-by-step.
   - Unmasks cloaked landing pages and shorteners (`bit.ly`, `tinyurl`, `t.co`, `is.gd`, `cutt.ly`).
   - Built with strict header-only parsing to isolate against client-side exploitation.

2. **Lexical Phishing Heuristics Engine:**
   - **IDN / Punycode Homograph Attacks:** Detects spoofed internationalized domain characters (`xn--...`).
   - **Deceptive Brand Hijacking:** Flags brand names in subdomains or paths when the true registered root domain belongs to an attacker (e.g., `instagram.com.security-check.xyz`).
   - **Direct IP Hostnames:** Flags URLs pointing to raw IPv4/IPv6 addresses.
   - **High-Risk TLD Scoring:** Penalizes TLDs heavily correlated with spam and malware campaigns (`.xyz`, `.top`, `.click`, `.buzz`, `.club`, `.work`).
   - **Credential Harvesting Keywords:** Detects urgency and verification triggers (`verify`, `suspend`, `appeal`, `login`, `banking`).

3. **Domain & DNS Forensic Intelligence:**
   - Performs DNS resolution to verify host availability, enumerate active IP addresses, and flag unreachable or disposable domains.

4. **Unified Phishing Risk Score ($0 - 100\%$):**
   - Combines lexical indicators, redirection depth, and host reputation into an actionable risk classification (*Benign*, *Suspicious*, *High-Risk*, *CRITICAL*).

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install requirements:
```bash
git clone https://github.com/shirazinator/sentinark-trace.git
cd sentinark-trace
pip install -r requirements.txt
```

### 2. Launch Interactive Web Dashboard
Run the threat intelligence console:
```bash
python3 -m sentinark_trace.web_app
```
Open your browser at: `http://127.0.0.1:5003`

### 3. CLI Terminal Inspection
Scan any suspicious link directly from your terminal:
```bash
python3 -m sentinark_trace.cli "http://instagram.com.account-update.xyz/login?id=urgent"
```

---

## 🧪 Unit Testing

Run unit tests across lexical heuristics, DNS resolution, and threat scoring:
```bash
python3 -m unittest discover -s tests
```

---

## 🛡️ Security Disclaimer
Sentinark-Trace performs passive network and lexical reconnaissance. It does not execute client-side scripts (such as JavaScript) or download executable binaries. It is built strictly for cybersecurity analysts, SOC teams, and users inspecting suspicious communications.

---

## 📄 License
This project is licensed under the MIT License.
