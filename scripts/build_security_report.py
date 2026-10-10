
import json
from datetime import datetime, timezone
from pathlib import Path

REPORTS = Path("reports")


def load_json(filename):
    path = REPORTS / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path}. Run the corresponding audit first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    storage = load_json("storage_audit.json")
    iam = load_json("iam_audit.json")

    storage_summary = storage["summary"]
    iam_count = iam["assignments_reviewed"]
    iam_flagged = sum(item.get("review_required", False) for item in iam.get("assignments", []))

    lines = [
        "# Cloud Security Assessment",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Scope",
        "",
        "This assessment covers selected Azure Storage configuration "
        "controls and a read-only review of role assignments returned "
        "by Azure CLI.",
        "",
        "Sensitive account, tenant, subscription, and principal "
        "identifiers are intentionally omitted from this report.",
        "",
        "## Storage security checks",
        "",
        "| Result | Count |",
        "|---|---:|",
        f"| Passed | {storage_summary['passed']} |",
        f"| Failed | {storage_summary['failed']} |",
        f"| Total | {storage_summary['total']} |",
        "",
        "## IAM review",
        "",
        f"- Assignments reviewed: {iam_count}",
        f"- Assignments flagged for human review: {iam_flagged}",
        "",
        "IAM flags are review prompts, not confirmed vulnerabilities. "
        "Role appropriateness depends on the principal, scope, inheritance, "
        "and operational need.",
        "",
        "## Limitations",
        "",
        "- This is a focused lab assessment, not a complete Azure security audit.",
        "- The checks cover only the controls implemented in the scripts.",
        "- No permissions were modified by the audit scripts.",
        "- Raw audit outputs may contain sensitive identifiers and should "
        "not be published without review and redaction.",
        "",
        "## Next actions",
        "",
        "1. Review any failed storage checks.",
        "2. Investigate flagged IAM assignments with appropriate context.",
        "3. Test the auditor using controlled test cases.",
        "4. Re-run the audit after remediation and compare results.",
        "",
    ]

    output = REPORTS / "security_assessment.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Combined report created: {output}")


if __name__ == "__main__":
    main()
