
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ACCOUNT = "stcloudlab13uvsingh"
RESOURCE_GROUP = "rg-cloud-security-lab"

def run_az(args):
    result = subprocess.run(
        ["az", *args],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)

def main():
    account = run_az([
        "storage", "account", "show",
        "--name", ACCOUNT,
        "--resource-group", RESOURCE_GROUP,
        "--query", "{id:id,name:name}",
        "-o", "json"
    ])

    assignments = run_az([
        "role", "assignment", "list",
        "--scope", account["id"],
        "--include-inherited",
        "-o", "json"
    ])

    reviewed = []
    for item in assignments:
        role = item.get("roleDefinitionName", "Unknown")
        scope = item.get("scope", "Unknown")
        principal_type = item.get("principalType", "Unknown")

        reviewed.append({
            "role": role,
            "scope": scope,
            "principal_type": principal_type,
            "review_required": role in {
                "Owner",
                "Contributor",
                "User Access Administrator",
                "Storage Blob Data Owner",
                "Storage Blob Data Contributor"
            }
        })

    report = {
        "account": ACCOUNT,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "assignments_reviewed": len(reviewed),
        "note": (
            "Review flags identify powerful roles for human assessment. "
            "They do not prove a permission is excessive."
        ),
        "assignments": reviewed
    }

    path = Path("reports/iam_audit.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    flagged = sum(x["review_required"] for x in reviewed)
    print(f"Assignments reviewed: {len(reviewed)}")
    print(f"Assignments flagged for review: {flagged}")
    print(f"Report saved to: {path}")

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, json.JSONDecodeError) as error:
        print(f"IAM audit failed: {error}")
        raise SystemExit(1)
