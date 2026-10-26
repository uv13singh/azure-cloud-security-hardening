# Repository Guidelines

## Project Structure

- `scripts/` contains Python storage, IAM, and Activity Log audits, shared checks, the remediation demo, and `test_storage_audit.py`.
- `terraform/` contains the Azure Storage security baseline, variables, and Terraform-specific guidance. Use `terraform.tfvars.example` as a starting point for local configuration.
- `reports/` holds generated and reviewed findings. Raw identity and Activity Log exports are ignored because they may expose account or resource details.
- `docs/` is for supporting project documentation. The root `README.md` describes goals, controls, and workflows.

## Build, Test, and Development

Run Python tests from the repository root:

```bash
PYTHONPATH=scripts python -m unittest discover -s scripts -p "test_*.py" -v
```

Run the local simulation with `python scripts/remediation_demo.py`; it uses simulated data and does not modify Azure. Run a live storage audit with `python scripts/storage_audit.py` or review recent events with `python scripts/activity_log_audit.py --days 7`; these require Azure CLI authentication and appropriate permissions. Review and sanitize generated reports before committing.

For infrastructure checks, run `terraform fmt`, `terraform init`, and `terraform validate` from `terraform/`. Inspect `terraform plan` and its target and cost implications before any deployment.

## Coding Style and Naming

Use four spaces for Python indentation, descriptive `snake_case` module and function names, and `test_*.py` test files with `test_*` methods. Keep audit logic testable and separate from Azure access where practical. Format Terraform with `terraform fmt`; keep variables and resource names descriptive and consistent with existing files.

## Testing Guidelines

Tests use Python's standard-library `unittest` framework. Cover expected secure settings and representative insecure or missing values when changing checks. Run the full discovery command above after changes; no coverage threshold is configured. Terraform changes should pass formatting and validation before review.

## Commits and Pull Requests

Git history uses short, imperative commit subjects (for example, `Add read-only Azure IAM audit`). Follow that pattern. Pull requests should explain the security impact, list validation commands and results, identify any Azure or Terraform changes, and include sanitized report excerpts when useful. Never include credentials, tokens, Terraform state, or raw identity/activity exports.

## Security and Configuration

Keep secrets in local environment or Azure CLI configuration, not source control. Do not weaken live controls to demonstrate findings; use the remediation simulation for that purpose. Treat IAM and keyword-based Activity Log findings as prompts for human review rather than confirmed vulnerabilities.
