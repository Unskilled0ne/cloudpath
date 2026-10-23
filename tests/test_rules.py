import os
import unittest
from cloudpath.analyzer import CloudPathAnalyzer

class TestCloudPathRules(unittest.TestCase):
    def setUp(self):
        fixture_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "fixtures",
            "cloudgoat_iam_privesc.json"
        )
        self.analyzer = CloudPathAnalyzer.from_file(fixture_path)
        self.results = self.analyzer.analyze()

    def test_passrole_compute_detection(self):
        findings = [f for f in self.results["escalation_paths"] if f["rule_id"] == "CP-ESC-01"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("dev-lambda-runner" in f["source_identity"] for f in findings))
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_create_access_key_detection(self):
        findings = [f for f in self.results["escalation_paths"] if f["rule_id"] == "CP-ESC-02"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("intern-security" in f["source_identity"] for f in findings))

    def test_direct_policy_attach_detection(self):
        findings = [f for f in self.results["escalation_paths"] if f["rule_id"] == "CP-ESC-03"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("ci-deployer" in f["source_identity"] for f in findings))

    def test_multi_hop_assumerole_chain(self):
        findings = [f for f in self.results["escalation_paths"] if f["rule_id"] == "CP-ESC-04"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("audit-contractor" in f["source_identity"] for f in findings))

    def test_wildcard_trust_detection(self):
        findings = [f for f in self.results["escalation_paths"] if f["rule_id"] == "CP-ESC-05"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("vendor-data-sync" in f["target_identity"] for f in findings))

    def test_hygiene_no_mfa_and_stale_keys(self):
        hygiene = self.results["hygiene_findings"]
        mfa_issues = [h for h in hygiene if h["rule_id"] == "CP-HYG-01"]
        stale_issues = [h for h in hygiene if h["rule_id"] == "CP-HYG-02"]
        self.assertGreaterEqual(len(mfa_issues), 1)
        self.assertGreaterEqual(len(stale_issues), 1)
        self.assertTrue(any("dev-lambda-runner" in h["identity"] for h in stale_issues))

if __name__ == "__main__":
    unittest.main()
