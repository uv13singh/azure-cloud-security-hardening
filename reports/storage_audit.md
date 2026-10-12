# Azure Storage Security Audit

- **Account:** `storage-account-anonymous`
- **Resource group:** `resource-group-anonymous`
- **Location:** `northcentralus`
- **Audit time (UTC):** 2026-10-12T01:28:08.104822+00:00

## Summary

| Passed | Failed | Total |
|---:|---:|---:|
| 5 | 0 | 5 |

## Findings

| Status | Severity | Check | Actual value |
|---|---|---|---|
| PASS | None | Public network access disabled | `Disabled` |
| PASS | None | Anonymous Blob access disabled | `False` |
| PASS | None | Minimum TLS version is 1.2 | `TLS1_2` |
| PASS | None | Secure transfer required | `True` |
| PASS | None | Storage account key access disabled | `False` |

## Remediation guidance

### Public network access disabled
- **Status:** PASS
- **Severity:** None
- **Expected:** `Disabled`
- **Observed:** `Disabled`
- **Recommendation:** Restrict public network access and verify required access paths.

### Anonymous Blob access disabled
- **Status:** PASS
- **Severity:** None
- **Expected:** `False`
- **Observed:** `False`
- **Recommendation:** Disable anonymous Blob access at the account level.

### Minimum TLS version is 1.2
- **Status:** PASS
- **Severity:** None
- **Expected:** `TLS1_2`
- **Observed:** `TLS1_2`
- **Recommendation:** Set the minimum TLS version to TLS 1.2 or higher.

### Secure transfer required
- **Status:** PASS
- **Severity:** None
- **Expected:** `True`
- **Observed:** `True`
- **Recommendation:** Require secure transfer for storage requests.

### Storage account key access disabled
- **Status:** PASS
- **Severity:** None
- **Expected:** `False`
- **Observed:** `False`
- **Recommendation:** Prefer Microsoft Entra authorization after checking workload compatibility.
