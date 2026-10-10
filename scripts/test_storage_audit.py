
import unittest

def evaluate(config):
    checks = {
        "public_network_disabled":
            config.get("publicNetworkAccess") == "Disabled",
        "anonymous_access_disabled":
            config.get("allowBlobPublicAccess") is False,
        "tls_12":
            config.get("minimumTlsVersion") == "TLS1_2",
        "https_only":
            config.get("httpsOnly") is True,
        "shared_key_disabled":
            config.get("allowSharedKeyAccess") is False,
    }
    return checks


class StorageAuditTests(unittest.TestCase):
    def setUp(self):
        self.secure_config = {
            "publicNetworkAccess": "Disabled",
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "httpsOnly": True,
            "allowSharedKeyAccess": False,
        }

    def test_secure_configuration_passes_all_checks(self):
        results = evaluate(self.secure_config)
        self.assertTrue(all(results.values()))

    def test_public_network_access_is_detected(self):
        config = self.secure_config.copy()
        config["publicNetworkAccess"] = "Enabled"
        results = evaluate(config)
        self.assertFalse(results["public_network_disabled"])

    def test_anonymous_access_is_detected(self):
        config = self.secure_config.copy()
        config["allowBlobPublicAccess"] = True
        results = evaluate(config)
        self.assertFalse(results["anonymous_access_disabled"])

    def test_old_tls_version_is_detected(self):
        config = self.secure_config.copy()
        config["minimumTlsVersion"] = "TLS1_0"
        results = evaluate(config)
        self.assertFalse(results["tls_12"])

    def test_https_requirement_is_detected(self):
        config = self.secure_config.copy()
        config["httpsOnly"] = False
        results = evaluate(config)
        self.assertFalse(results["https_only"])

    def test_shared_key_access_is_detected(self):
        config = self.secure_config.copy()
        config["allowSharedKeyAccess"] = True
        results = evaluate(config)
        self.assertFalse(results["shared_key_disabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
