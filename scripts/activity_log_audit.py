import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess

def run_az(args):
    result = subprocess.run(
        ["az"] + args + ["--output", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else None

def main():
    parser = argparse.ArgumentParser(
        description="Collect Azure Activity Log events for security review."
    )
    parser.add_argument(
        "--resource-group",
        default="rg-cloud-security-lab",
        help="Azure resource group to review",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Look-back window in days (1-90)",
    )
    args = parser.parse_args()

    if not 1 <= args.days <= 90:
        parser.error("--days must be between 1 and 90")

    events = run_az([
        "monitor", "activity-log", "list",
        "--resource-group", args.resource_group,
        "--offset", f"{args.days}d",
        "--max-events", "100",
        "--output", "json",
    ])

    events = events or []
    keywords = (
        "write", "delete", "role assignment",
        "policy", "firewall", "network",
        "storage account", "security",
    )

    reviewed = []
    for event in events:
        operation = (
            event.get("operationName", {}).get("localizedValue", "")
            if isinstance(event.get("operationName"), dict)
            else str(event.get("operationName", ""))
        )
        status = (
            event.get("status", {}).get("localizedValue", "")
            if isinstance(event.get("status"), dict)
            else str(event.get("status", ""))
        )

        if any(word in operation.lower() for word in keywords):
            reviewed.append({
                "time": event.get("eventTimestamp"),
                "operation": operation,
                "status": status,
                "caller": event.get("caller"),
                "resourceId": event.get("resourceId"),
                "correlationId": event.get("correlationId"),
            })

    output = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "resourceGroup": args.resource_group,
        "lookbackDays": args.days,
        "eventsRetrieved": len(events),
        "securityRelevantEvents": len(reviewed),
        "events": reviewed,
        "note": (
            "Keyword-based triage only; this is not a complete threat "
            "detection system. Validate events and identities in Azure."
        ),
    }

    report_path = Path("reports") / "activity_log_audit.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(output, indent=2) + "\n")

    print(f"Events retrieved: {len(events)}")
    print(f"Events flagged for review: {len(reviewed)}")
    print(f"Report saved: {report_path}")


if __name__ == "__main__":
    main()