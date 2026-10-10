import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ACCOUNT = "stcloudlab13uvsingh"
RESOURCE_GROUP = "rg-cloud-security-lab"

def audit_storage():
    query = (
        "{name:name,"
        "location:location,"
        "publicNetworkAccess:publicNetworkAccess,"
        "allowBlobPublicAccess:allowBlobPublicAccess,"
        "minimumTlsVersion:minimumTlsVersion,"
        "httpsOnly:enableHttpsTrafficOnly,"
        "allowSharedKeyAccess:allowSharedKeyAccess}"
    )

    command = [
        "az", "storage", "account", "show",
        "--name", ACCOUNT,
        "--resource-group", RESOURCE_GROUP,
        "--query", query,
        "--output", "json"
    ]

    result = subprocess.run(
        command, capture_output=True, text=True
    )

    if result.returncode != 0:
        print("Azure query failed:")
        print(result.stderr)
        return

    config = json.loads(result.stdout)
    findings = []

    def check(condition, title, severity, detail):
        findings.append({
            "check": title,
            "status": "PASS" if condition else "FAIL",
            "severity": severity if not condition else "None",
            "details": detail
        })

    check(
        config.get("publicNetworkAccess") == "Disabled",
        "Public network access disabled",
        "High",
        f"Current value: {config.get('publicNetworkAccess')}"
    )

    check(
        config.get("allowBlobPublicAccess") is False,
        "Anonymous Blob access disabled",
        "High",
        f"Current value: {config.get('allowBlobPublicAccess')}"
    )

    check(
        config.get("minimumTlsVersion") == "TLS1_2",
        "Minimum TLS version is 1.2 or higher",
        "Medium",
        f"Current value: {config.get('minimumTlsVersion')}"
    )

    check(
        config.get("httpsOnly") is True,
        "Secure transfer required",
        "High",
        f"Current value: {config.get('httpsOnly')}"
    )

    check(
        config.get("allowSharedKeyAccess") is False,
        "Storage account key access disabled",
        "Medium",
        f"Current value: {config.get('allowSharedKeyAccess')}"
    )

    report = {
        "account": ACCOUNT,
        "resource_group": RESOURCE_GROUP,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": config,
        "summary": {
            "passed": sum(f["status"] == "PASS" for f in findings),
            "failed": sum(f["status"] == "FAIL" for f in findings),
            "total": len(findings)
        },
        "findings": findings
    }

    output = Path("reports/storage_audit.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))

    print(json.dumps(report["summary"], indent=2))
    print(f"\nFull report saved to: {output}")

if __name__ == "__main__":
    audit_storage()
