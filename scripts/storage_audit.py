import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from storage_checks import evaluate_configuration

ACCOUNT = "stcloudlab13uvsingh"
RESOURCE_GROUP = "rg-cloud-security-lab"

CHECKS = [
    {
        "key": "publicNetworkAccess",
        "name": "Public network access disabled",
        "expected": "Disabled",
        "severity": "High",
        "remediation": "Restrict public network access. Confirm required access paths before changing networking."
    },
    {
        "key": "allowBlobPublicAccess",
        "name": "Anonymous Blob access disabled",
        "expected": False,
        "severity": "High",
        "remediation": "Disable anonymous Blob access at the storage account level."
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
        "remediation": "Enable secure transfer to require encrypted HTTPS connections."
    },
    {
        "key": "allowSharedKeyAccess",
        "name": "Storage account key access disabled",
        "expected": False,
        "severity": "Medium",
        "remediation": "Prefer Microsoft Entra ID authorization. Confirm workloads do not depend on Shared Key before disabling it."
    },
]


def get_configuration():
    query = (
        "{name:name,location:location,"
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

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Azure CLI query failed")

    return json.loads(result.stdout)


def main():
    try:
        config = get_configuration()
    except (RuntimeError, json.JSONDecodeError) as error:
        print(f"Audit failed: {error}")
        print("Check that Azure CLI is installed, you are signed in, and the correct subscription is active.")
        raise SystemExit(1)

    findings = evaluate_configuration(config)

    passed_count = sum(item["status"] == "PASS" for item in findings)
    failed_count = len(findings) - passed_count

    report = {
        "account": ACCOUNT,
        "resource_group": RESOURCE_GROUP,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": config,
        "summary": {
            "passed": passed_count,
            "failed": failed_count,
            "total": len(findings)
        },
        "findings": findings
    }

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "storage_audit.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    lines = [
        "# Azure Storage Security Audit",
        "",
        f"- **Account:** `{ACCOUNT}`",
        f"- **Resource group:** `{RESOURCE_GROUP}`",
        f"- **Location:** `{config.get('location')}`",
        f"- **Audit time (UTC):** {report['timestamp_utc']}",
        "",
        "## Summary",
        "",
        "| Passed | Failed | Total |",
        "|---:|---:|---:|",
        f"| {passed_count} | {failed_count} | {len(findings)} |",
        "",
        "## Findings",
        "",
        "| Status | Severity | Check | Actual value |",
        "|---|---|---|---|",
    ]

    for item in findings:
        lines.append(
            f"| {item['status']} | {item['severity']} | "
            f"{item['check']} | `{item['actual_value']}` |"
        )

    lines.extend(["", "## Remediation guidance", ""])

    for item in findings:
        lines.extend([
            f"### {item['check']}",
            f"- **Status:** {item['status']}",
            f"- **Severity:** {item['severity']}",
            f"- **Expected:** `{item['expected_value']}`",
            f"- **Observed:** `{item['actual_value']}`",
            f"- **Recommendation:** {item['remediation']}",
            ""
        ])

    (output_dir / "storage_audit.md").write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    print(f"Audit complete: {passed_count} passed, {failed_count} failed.")
    print("JSON report: reports/storage_audit.json")
    print("Markdown report: reports/storage_audit.md")


if __name__ == "__main__":
    main()