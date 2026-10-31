"""
Unit tests for Sentinark-Trace core engine.
"""

import unittest
from sentinark_trace.heuristics import analyze_url_heuristics
from sentinark_trace.threat_scorer import calculate_phishing_threat
from sentinark_trace.domain_intel import resolve_domain_intel


class TestSentinarkTrace(unittest.TestCase):

    def test_benign_url_heuristics(self):
        res = analyze_url_heuristics("https://github.com/shirazinator")
        self.assertEqual(res["penalty_score"], 0)
        self.assertEqual(len(res["flags"]), 0)

    def test_phishing_brand_spoofing(self):
        res = analyze_url_heuristics("http://instagram.com.account-update.xyz/login")
        self.assertTrue(res["is_suspicious"])
        self.assertGreater(res["penalty_score"], 40)
        # Should detect brand spoofing and risky TLD
        flag_str = " ".join(res["flags"])
        self.assertTrue("instagram" in flag_str.lower())
        self.assertTrue("xyz" in flag_str.lower() or "tld" in flag_str.lower())

    def test_ip_address_hostname(self):
        res = analyze_url_heuristics("http://192.168.1.1/admin/login")
        self.assertTrue(any("IP address" in f for f in res["flags"]))

    def test_punycode_detection(self):
        res = analyze_url_heuristics("https://xn--appl-43d.com/secure")
        self.assertTrue(any("Punycode" in f for f in res["flags"]))

    def test_domain_intel_resolution(self):
        intel = resolve_domain_intel("127.0.0.1")
        self.assertIn("127.0.0.1", intel["resolved_ips"])
        self.assertEqual(intel["dns_status"], "RESOLVED")

    def test_threat_scorer(self):
        redirect_mock = {
            "initial_url": "http://short.ly/xyz",
            "final_url": "http://evil-instagram.xyz/login",
            "total_hops": 2,
            "hops": [],
            "uses_shortener": True,
            "multiple_redirects": True
        }
        heuristic_mock = {
            "penalty_score": 60,
            "flags": ["Deceptive Brand", "Suspicious TLD"]
        }
        domain_mock = {"hostname": "evil-instagram.xyz", "dns_status": "RESOLVED", "resolved_ips": ["1.2.3.4"]}

        threat = calculate_phishing_threat(redirect_mock, heuristic_mock, domain_mock)
        self.assertGreaterEqual(threat["threat_score"], 75.0)
        self.assertIn("CRITICAL", threat["risk_tier"])


if __name__ == "__main__":
    unittest.main()
