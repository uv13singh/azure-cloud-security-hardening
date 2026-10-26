import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from storage_checks import CHECKS, evaluate_configuration

ACCOUNT_ENV = "AZURE_STORAGE_ACCOUNT"
RESOURCE_GROUP_ENV = "AZURE_RESOURCE_GROUP"


def get_configuration(account, resource_group):
    query = (
        "{location:location,"
        "publicNetworkAccess:publicNetworkAccess,"
        "allowBlobPublicAccess:allowBlobPublicAccess,"
        "minimumTlsVersion:minimumTlsVersion,"
        "httpsOnly:enableHttpsTrafficOnly,"
        "allowSharedKeyAccess:allowSharedKeyAccess}"
    )

    command = [
        "az", "storage", "account", "show",
        "--name", account,
        "--resource-group", resource_group,
        "--query", query,
        "--output", "json"
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Azure CLI query failed")

    return json.loads(result.stdout)


def build_report(config, findings, timestamp=None):
    """Build a report that contains control results but no resource identity."""
    safe_configuration = {"location": config.get("location")}
    safe_configuration.update(
        (check["key"], config.get(check["key"])) for check in CHECKS
    )

    passed_count = sum(item["status"] == "PASS" for item in findings)
    return {
        "account": "REDACTED",
        "resource_group": "REDACTED",
        "timestamp_utc": timestamp or datetime.now(timezone.utc).isoformat(),
        "configuration": safe_configuration,
        "summary": {
            "passed": passed_count,
            "failed": len(findings) - passed_count,
            "total": len(findings),
        },
        "findings": findings,
    }


def main():
    account = os.environ.get(ACCOUNT_ENV)
    resource_group = os.environ.get(RESOURCE_GROUP_ENV)
    if not account or not resource_group:
        print(
            f"Set {ACCOUNT_ENV} and {RESOURCE_GROUP_ENV} before running the audit."
        )
        raise SystemExit(1)

    try:
        config = get_configuration(account, resource_group)
    except (FileNotFoundError, RuntimeError, json.JSONDecodeError) as error:
        print(f"Audit failed: {error}")
        print("Check that Azure CLI is installed, you are signed in, and the correct subscription is active.")
        raise SystemExit(1)

    findings = evaluate_configuration(config)
    report = build_report(config, findings)
    passed_count = report["summary"]["passed"]
    failed_count = report["summary"]["failed"]

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "storage_audit.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    lines = [
        "# Azure Storage Security Audit",
        "",
        "- **Account:** `REDACTED`",
        "- **Resource group:** `REDACTED`",
        f"- **Location:** `{report['configuration'].get('location')}`",
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
