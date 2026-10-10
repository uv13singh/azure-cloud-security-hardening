
import unittest
from storage_checks import evaluate_configuration


class StorageAuditTests(unittest.TestCase):
    def setUp(self):
        self.secure_config = {
            "publicNetworkAccess": "Disabled",
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "httpsOnly": True,
            "allowSharedKeyAccess": False,
        }

    def get_results(self, config):
        return {
            finding["check"]: finding
            for finding in evaluate_configuration(config)
        }

    def test_secure_configuration_passes_all_checks(self):
        findings = evaluate_configuration(self.secure_config)
        self.assertEqual(len(findings), 5)
        self.assertTrue(
            all(finding["status"] == "PASS" for finding in findings)
        )

    def test_public_network_access_is_detected(self):
        config = self.secure_config.copy()
        config["publicNetworkAccess"] = "Enabled"
        results = self.get_results(config)
        self.assertEqual(
            results["Public network access disabled"]["status"], "FAIL"
        )

    def test_anonymous_blob_access_is_detected(self):
        config = self.secure_config.copy()
        config["allowBlobPublicAccess"] = True
        results = self.get_results(config)
        self.assertEqual(
            results["Anonymous Blob access disabled"]["status"], "FAIL"
        )

    def test_old_tls_version_is_detected(self):
        config = self.secure_config.copy()
        config["minimumTlsVersion"] = "TLS1_0"
        results = self.get_results(config)
        self.assertEqual(
            results["Minimum TLS version is 1.2"]["status"], "FAIL"
        )

    def test_https_requirement_is_detected(self):
        config = self.secure_config.copy()
        config["httpsOnly"] = False
        results = self.get_results(config)
        self.assertEqual(
            results["Secure transfer required"]["status"], "FAIL"
        )

    def test_shared_key_access_is_detected(self):
        config = self.secure_config.copy()
        config["allowSharedKeyAccess"] = True
        results = self.get_results(config)
        self.assertEqual(
            results["Storage account key access disabled"]["status"], "FAIL"
        )

    def test_multiple_misconfigurations_are_detected(self):
        config = self.secure_config.copy()
        config["publicNetworkAccess"] = "Enabled"
        config["allowBlobPublicAccess"] = True
        config["httpsOnly"] = False

        findings = evaluate_configuration(config)
        failed = [item for item in findings if item["status"] == "FAIL"]

        self.assertEqual(len(failed), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)