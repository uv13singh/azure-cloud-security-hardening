
import json
from pathlib import Path
from storage_checks import evaluate_configuration


SECURE_CONFIG = {
    "publicNetworkAccess": "Disabled",
    "allowBlobPublicAccess": False,
    "minimumTlsVersion": "TLS1_2",
    "httpsOnly": True,
    "allowSharedKeyAccess": False,
}

# Simulated insecure settings for a safe local demonstration.
INSECURE_CONFIG = {
    **SECURE_CONFIG,
    "publicNetworkAccess": "Enabled",
    "allowBlobPublicAccess": True,
    "minimumTlsVersion": "TLS1_0",
    "httpsOnly": False,
    "allowSharedKeyAccess": True,
}


def summarize(config):
    findings = evaluate_configuration(config)
    passed = sum(item["status"] == "PASS" for item in findings)
    failed = sum(item["status"] == "FAIL" for item in findings)

    return {
        "passed": passed,
        "failed": failed,
        "total": len(findings),
        "findings": findings,
    }


def main():
    before = summarize(INSECURE_CONFIG)
    after = summarize(SECURE_CONFIG)

    report = {
        "title": "Simulated Storage Security Remediation",
        "scope": "Local simulation; no Azure settings were changed.",
        "before_remediation": before,
        "after_remediation": after,
        "failed_checks_resolved": before["failed"] - after["failed"],
    }

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / "remediation_demo.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n")

    print("Simulated remediation complete")
    print(
        f"Before: {before['passed']} passed, "
        f"{before['failed']} failed"
    )
    print(
        f"After:  {after['passed']} passed, "
        f"{after['failed']} failed"
    )
    print(f"Failed checks resolved: {report['failed_checks_resolved']}")
    print(f"Report saved: {output_path}")


if __name__ == "__main__":
    main()