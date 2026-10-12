
# Azure Cloud Security Hardening

## Project Overview

This project demonstrates how to define secure Azure Storage infrastructure using Terraform and evaluate cloud security configurations with Python.

The goal is to make security controls repeatable, testable, and easier to audit.

## Security Controls

| Control | Secure Configuration | Security Benefit |
|---|---|---|
| Minimum TLS | TLS 1.2 | Reduces use of older transport protocols |
| HTTPS-only traffic | Enabled | Requires encrypted connections |
| Anonymous Blob access | Disabled | Prevents anonymous public Blob access |
| Shared Key authorization | Disabled | Reduces reliance on account keys |
| Public network access | Disabled | Blocks access through the public network endpoint |

## Infrastructure Design

Terraform defines a separate storage account in the existing lab resource group.

- Resource group: `rg-cloud-security-lab`
- Region: 'northcentralus'
- Performance tier: Standard
- Redundancy: Locally redundant storage (LRS)
- Network access: Public network access disabled

The Terraform baseline has been deployed to Azure and verified against
the live storage account. A subsequent Terraform plan reported no changes.

Verified controls include TLS 1.2, HTTPS-only traffic, disabled anonymous
Blob access, disabled Shared Key access, disabled public network access,
Microsoft Entra ID as the default portal authorization method, and
disabled local-user authentication.

The initial deployment encountered a data-plane authentication error
because Shared Key access was disabled. The resource was reconciled with
Terraform state, and the final plan reported no changes without weakening
the security settings.

## Validation

From the `terraform/` directory:

```bash
terraform fmt
terraform init
terraform validate
```

Before deployment, review the Terraform plan and confirm the target resource names, security settings, permissions, and estimated costs.

## Python Security Auditing

The Python audit scripts evaluate storage security settings against expected values and produce structured findings.

The project also includes:
- Unit tests for secure and insecure configurations
- A local remediation simulation
- An IAM role-assignment review
- A combined security assessment report

The remediation simulation does not change live Azure resources.

## Safety and Scope

- Do not commit credentials, tokens, or raw IAM reports.
- Do not weaken the live storage account to simulate a vulnerability.
- Do not deploy infrastructure until the plan and cost implications have been reviewed.
- Treat flagged IAM assignments as items for human review, not automatically confirmed vulnerabilities.

## Current Limitations

- Terraform deployment has not yet been performed.
- The Terraform baseline has not yet been verified against a deployed Terraform-managed resource.
- Security findings should be interpreted in the context of the lab's scope and permissions.

## Future Improvements

- Review a Terraform plan before deployment.
- Add automated tests for security-control evaluation.
- Capture sanitized before-and-after remediation evidence.
- Document setup, execution, and cleanup procedures.