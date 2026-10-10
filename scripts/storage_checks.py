
CHECKS = [
    {
        "key": "publicNetworkAccess",
        "name": "Public network access disabled",
        "expected": "Disabled",
        "severity": "High",
        "remediation": "Restrict public network access and verify required access paths."
    },
    {
        "key": "allowBlobPublicAccess",
        "name": "Anonymous Blob access disabled",
        "expected": False,
        "severity": "High",
        "remediation": "Disable anonymous Blob access at the account level."
    },
    {
        "key": "minimumTlsVersion",
        "name": "Minimum TLS version is 1.2",
        "expected": "TLS1_2",
        "severity": "Medium",
        "remediation": "Set the minimum TLS version to TLS 1.2 or higher."
    },
    {
        "key": "httpsOnly",
        "name": "Secure transfer required",
        "expected": True,
        "severity": "High",
        "remediation": "Require secure transfer for storage requests."
    },
    {
        "key": "allowSharedKeyAccess",
        "name": "Storage account key access disabled",
        "expected": False,
        "severity": "Medium",
        "remediation": "Prefer Microsoft Entra authorization after checking workload compatibility."
    },
]


def evaluate_configuration(config):
    findings = []

    for check in CHECKS:
        actual = config.get(check["key"])
        passed = actual == check["expected"]

        findings.append({
            "check": check["name"],
            "status": "PASS" if passed else "FAIL",
            "severity": "None" if passed else check["severity"],
            "actual_value": actual,
            "expected_value": check["expected"],
            "remediation": check["remediation"],
        })

    return findings