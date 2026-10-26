# Azure Cloud Security Hardening & Auditing
A hands-on cloud security project focused on hardening Azure Storage, validating security configurations with Python, reviewing identity and access permissions, and auditing Azure Activity Logs.

## Project Goals
- Apply security hardening controls to an Azure Storage Account using Terraform.
- Automate checks for common cloud storage misconfigurations.
- Review Azure role assignments for permissions that need additional scrutiny.
- Collect and triage Azure Activity Log events.
- Demonstrate remediation of insecure configurations through repeatable tests.

## Architecture
Azure Subscription
       |
       v
Terraform Security Baseline
       |
       v
Azure Storage Account
       |
       +--> Storage Configuration Audit (Python)
       |
       +--> IAM Role Assignment Review
       |
       +--> Azure Activity Log Triage
       |
       v
Security Reports & Remediation Demo

## Security Controls
The deployed storage account was verified against these controls:

| Control | Expected configuration |
|---|---|
| Public network access | Disabled |
| Anonymous Blob access | Disabled |
| Minimum TLS version | TLS 1.2 |
| HTTPS-only traffic | Enabled |
| Shared Key access | Disabled |
| Default portal authorization | Microsoft Entra ID |
| Local-user authentication | Disabled |

## Tools and Technologies
- Microsoft Azure
- Terraform
- Python
- Azure CLI
- Git and GitHub
- Python `unittest`

## Automated Validation
The storage auditor evaluates five security controls and reports pass/fail results.

The unit tests cover secure configurations and deliberately insecure scenarios. A local remediation demo compares a simulated insecure configuration against a hardened one.

The Activity Log script retrieves recent Azure events and flags potentially relevant operations for manual review. Its keyword-based triage is a learning tool, not a full threat detection system.

## Reports
- `reports/storage_audit.md` — storage security findings
- `reports/security_assessment.md` — combined security assessment
- `reports/remediation_demo.json` — simulated remediation results

Raw identity and activity reports are excluded from version control because they may contain identifying information and Azure resource metadata.

## Reproducing the Checks
Prerequisites: Python 3, Azure CLI, an authenticated Azure account with suitable permissions, and Terraform for infrastructure management.

Run the unit tests:

```bash
PYTHONPATH=scripts python -m unittest discover -s scripts -p "test_*.py" -v
```

Run the storage audit:

```bash
export AZURE_STORAGE_ACCOUNT="<storage-account-name>"
export AZURE_RESOURCE_GROUP="<resource-group-name>"
python scripts/storage_audit.py
```

The storage audit reads the account and resource group from these environment
variables. Its generated reports redact both identifiers and include only the
location and checked security settings.

Run the remediation demonstration:

```bash
python scripts/remediation_demo.py
```

Review the last seven days of Azure Activity Log events:

```bash
python scripts/activity_log_audit.py --days 7
```

The audit scripts require an appropriate Azure login and permissions. The remediation demo uses simulated data and does not change Azure resources.

## Limitations
- IAM findings are flagged for human review and are not automatically confirmed vulnerabilities.
- Activity Log review is limited to the first 100 returned events. Keyword classification can produce false positives or miss relevant events.
- Disabling public network access may affect workloads that require network access; access paths should be planned before deployment.
- Defender for Storage was not enabled as part of this lab.

## Future Improvements
- Add automated tests for Activity Log parsing and filtering.
- Add policy-compliance checks and more detailed IAM analysis.
- Add a sanitized example report and screenshots of verified Azure settings.
- Integrate checks into a CI workflow.

## Disclaimer
This project is an educational cloud security lab. Review configurations, access requirements, and potential costs before deploying resources in a real Azure environment.
