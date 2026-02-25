# Entra ID & Google Workspace Security Bridge

**Repository:** [thomaselliottbetz/entra-google-security-bridge](https://github.com/thomaselliottbetz/entra-google-security-bridge)
**Target Environment:** Microsoft Entra ID + Google Workspace (Hybrid Identity)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Functional Domains](#functional-domains)
- [File Structure](#file-structure)
- [Requirements](#requirements)
- [Authentication Setup](#authentication-setup)
- [Required API Permissions](#required-api-permissions)
- [Usage Examples](#usage-examples)
- [Production-Ready Considerations](#production-ready-considerations)
- [Deployment Options](#deployment-options)
- [Limitations](#limitations)

---

## Overview

This repository bridges security operations and attribute synchronization between Microsoft Entra ID and Google Workspace. While SCIM handles initial user provisioning, these scripts address ongoing security monitoring and post-provisioning attribute sync needs.

The project is organized into three functional domains: Identity Governance (Entra ID), Post-Provisioning Sync (Cross-Platform), and Collaboration Security (Google Workspace).

---

## Architecture

```
Entra ID (Microsoft Graph API)          Google Workspace (Admin SDK)
         │                                        │
         │  OAuth 2.0 client credentials          │  Service account +
         │                                        │  domain-wide delegation
         ▼                                        ▼
┌─────────────────────┐              ┌────────────────────────────┐
│ identity_governance │  ──────────▶ │ collaboration_security_    │
│ _ms.py              │  user attrs  │ google.py                  │
│                     │              │                            │
│ • Risky sign-ins    │              │ • OU sync                  │
│ • Guest user audit  │              │ • OAuth token audit        │
│ • User attr query   │              │ • OU management            │
└─────────────────────┘              └────────────────────────────┘
         │                                        │
         └──────────── SIEM / SOAR ───────────────┘
              (Splunk, Sentinel, Google SecOps)
```

---

## Functional Domains

### 1. Identity Governance (Entra ID)

**Risky Sign-In Monitoring**

Detects suspicious sign-in patterns by querying Microsoft Identity Protection. Results include user email, risk level (low/medium/high), IP address, geographic location, and the specific risk event types that triggered the alert — for example, `anonymousIP` for VPN/Tor usage or `unfamiliarFeatures` for sign-ins from new locations.

Risk level filtering is applied in Python after retrieval rather than via OData lambda operators. The time-window filter uses indexed `createdDateTime` fields to minimize API latency and avoid 429 throttling. Full pagination via `@odata.nextLink` ensures no events are missed.

**Guest User Audit (Zero-Trust)**

Flags stale or untrusted external identities (B2B users) for access review or revocation. Guest users are identified by `userType eq 'Guest'` in Microsoft Graph and categorized by trust level (trusted vs. untrusted domains) and activity status (based on `lastSignInDateTime`), making it straightforward to prioritize removals for zero-trust compliance.

Note: `lastSignInDateTime` requires an Entra ID P1/P2 license. Users without a recorded sign-in date are treated as inactive.

**Tech Stack:** MSAL, Microsoft Graph API, OData

---

### 2. Post-Provisioning Sync (Cross-Platform)

**Attribute-Based OU Sync**

Queries Entra ID for users whose attributes (e.g., `department`, `officeLocation`) match a given OData filter, then synchronizes their Organizational Unit placement in Google Workspace. Assumes users already exist in Google Workspace, provisioned via SCIM or other means.

Authentication uses MSAL's OAuth 2.0 client credentials flow with automatic token management. The returned user data — `userPrincipalName`, `displayName`, `officeLocation`, `department`, `jobTitle` — drives the OU mapping logic on the Google side.

**Tech Stack:** OAuth 2.0, Service Accounts, Domain-Wide Delegation

---

### 3. Collaboration Security (Google Workspace)

**OU Management**

Provides tools for user relocation during role changes or incident response. Includes a simple move function (`move_user_to_ou`) and a pre-flight variant (`move_user_between_ous`) that verifies the user's current OU matches the expected source before proceeding. Suitable for scheduled execution, manual incident response, or HR workflow automation.

**Shadow IT / OAuth Token Audit**

Scans all users for high-risk OAuth grants (e.g., `drive.readonly`, `gmail.send`) and flags applications not on the approved allowlist. Each token record includes the application name, granted scopes, and whether the application is anonymous. Results are categorized into high-risk (blocked scopes, not approved), medium-risk (sensitive scopes from unknown apps), and low-risk (approved apps or safe scopes). Full pagination handles organizations with thousands of users.

**Tech Stack:** Google Admin SDK, Google Auth Library

---

## File Structure

| File | Description |
|------|-------------|
| `identity_governance_ms.py` | Risky sign-in monitoring, guest user audit, and Entra ID attribute query for post-provisioning sync |
| `collaboration_security_google.py` | Google Workspace OU management (`move_user_to_ou`, `move_user_between_ous`), OAuth token audit, and cross-platform OU sync |

---

## Requirements

### Python

Python 3.9 or later.

### Dependencies

```
msal>=1.24.0
google-auth>=2.23.0
google-api-python-client>=2.100.0
requests>=2.31.0
```

Install with:

```bash
pip install -r requirements.txt
```

---

## Authentication Setup

**Entra ID**
- App registration in Azure AD with appropriate API permissions
- Client ID, Client Secret, and Tenant ID

**Google Workspace**
- Service account with domain-wide delegation enabled
- Service account JSON key file
- Admin user email for impersonation — set via the `GOOGLE_ADMIN_EMAIL` environment variable

> **Note:** `GOOGLE_ADMIN_EMAIL` is required and validated at runtime. Functions raise a `ValueError` if it is not set.

---

## Required API Permissions

### Microsoft Graph

| Permission | Purpose |
|---|---|
| `IdentityRiskEvent.Read.All` | Risky sign-in monitoring |
| `User.Read.All` | User attribute queries |
| `Directory.Read.All` | Guest user audit |

All permissions require application-level grants with admin consent.

### Google Workspace

| Scope | Purpose |
|---|---|
| `admin.directory.user` | OU management (read/write) |
| `admin.directory.user.readonly` | User listing for OAuth token audit |
| `admin.directory.user.security` | OAuth token access — requires explicit approval in the Google Workspace admin console |

---

## Usage Examples

### Monitor Risky Sign-Ins

```python
from identity_governance_ms import get_risky_sign_ins

risky_signins = get_risky_sign_ins(
    tenant_id="your-tenant-id",
    client_id="your-app-client-id",
    client_secret="your-client-secret",
    hours_back=24,
    min_risk_level="medium"
)
```

### Audit Guest Users

```python
from identity_governance_ms import audit_guest_users

guest_report = audit_guest_users(
    tenant_id="your-tenant-id",
    client_id="your-app-client-id",
    client_secret="your-client-secret",
    trusted_domains=["bigenterprise.com", "partner-company.com"],
    days_inactive=90
)

# Returns a dictionary with keys: 'trusted_active', 'trusted_inactive',
# 'untrusted_active', 'untrusted_inactive'
print(f"Untrusted inactive guests: {len(guest_report.get('untrusted_inactive', []))}")
```

### Move User to Different OU

```python
import os
from collaboration_security_google import move_user_to_ou

os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@bigenterprise.com'

move_user_to_ou(
    user_email="engineer@bigenterprise.com",
    target_ou_path="/Engineering/ProjectA",
    credentials_path="/path/to/service_account.json"
)
```

### Move User with Pre-Flight Verification

```python
import os
from collaboration_security_google import move_user_between_ous

os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@bigenterprise.com'

move_user_between_ous(
    user_email="engineer@bigenterprise.com",
    source_org_unit_path="/Engineering",
    target_org_unit_path="/Engineering/ProjectA",
    credentials_path="/path/to/service_account.json"
)
```

### Audit OAuth Tokens

```python
import os
from collaboration_security_google import audit_oauth_tokens

os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@bigenterprise.com'

token_report = audit_oauth_tokens(
    credentials_path="/path/to/service_account.json",
    blocked_scopes=[
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/gmail.send'
    ],
    approved_apps=['Google Workspace', 'Slack', 'Microsoft']
)

# Returns a dictionary with keys: 'high_risk', 'medium_risk', 'low_risk'
print(f"High-risk tokens found: {len(token_report.get('high_risk', []))}")
```

### Query Entra ID for OU Updates

```python
from identity_governance_ms import get_entra_users_with_changes

users_needing_sync = get_entra_users_with_changes(
    tenant_id="your-tenant-id",
    client_id="your-app-client-id",
    client_secret="your-client-secret",
    filter_criteria="officeLocation eq 'Seattle' or department eq 'Engineering'"
)
```

### Sync Entra ID to Google Workspace OUs

```python
import os
from collaboration_security_google import sync_entra_to_google_ou

os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@bigenterprise.com'

result = sync_entra_to_google_ou(
    entra_tenant_id="your-tenant-id",
    entra_client_id="your-app-client-id",
    entra_client_secret="your-client-secret",
    google_credentials_path="/path/to/service_account.json",
    ou_mapping={
        "officeLocation": {
            "Seattle": "/Engineering/Seattle",
            "NYC": "/Engineering/NYC"
        }
    },
    filter_criteria="officeLocation eq 'Seattle' or officeLocation eq 'NYC'",
    email_domain_mapping={"@company.com": "@company.google.com"}  # optional
)

# Returns a dictionary with keys: 'synced', 'skipped', 'failed'
print(f"Synced: {len(result['synced'])} users")
print(f"Skipped (not in Google): {len(result['skipped'])} users")
print(f"Failed: {len(result['failed'])} users")

for user in result['synced']:
    print(f"{user['email']} moved from {user['previous_ou']} to {user['target_ou']}")
```

---

## Production-Ready Considerations

**API Resilience**
Full pagination via `@odata.nextLink` (Microsoft Graph) and `nextPageToken` (Google Admin SDK) ensures complete result sets in organizations with 10,000+ users.

**Idempotency & Pre-flight Checks**
Before applying changes, functions verify current state — for example, checking the user's current OU before moving — to prevent blind updates and unnecessary API calls. Users already in the target OU are skipped.

**Principle of Least Privilege**
Each function requests only the minimum scopes required. `admin.directory.user.security` is requested separately from general directory access rather than relying on broad Super Admin rights.

**Structured Logging**
All output uses Python's `logging` module with appropriate levels: `INFO` for status, `WARNING` for security findings, `ERROR` for failures. This makes the scripts ready for SIEM/SOAR integration out of the box (Splunk, Google SecOps, Microsoft Sentinel).

**Performance Optimization**
Complex filtering (e.g., risk level thresholds, domain matching) is applied in Python after retrieval rather than via OData lambda operators, ensuring reliable performance during high-traffic security events. Time-window queries target indexed fields to minimize response times.

**Portability**
The `my_customer` alias and environment-based admin impersonation keep the scripts tenant-agnostic and suitable for multi-region deployment.

---

## Deployment Options

- Scheduled jobs (cron, Task Scheduler)
- Python task schedulers (`schedule` library)
- Event-driven workflows triggered by security alerts
- Manual execution for incident response

---

## Limitations

- **Detection only:** These scripts report findings but do not perform automated remediation (e.g., revoking tokens, disabling accounts). Remediation is expected to be handled by downstream SOAR tooling or manual review.
- **Not real-time:** Queries are batch-oriented and designed for scheduled execution. For real-time event streaming, consider Microsoft Graph change notifications or Google Cloud Pub/Sub.
- **Requires existing provisioning:** `sync_entra_to_google_ou` assumes users already exist in Google Workspace. Initial provisioning is out of scope and expected to be handled via SCIM.
- **Entra ID P1/P2 required:** `lastSignInDateTime` (used for guest inactivity checks) is only available on premium tenants. Users without this data are treated as inactive.
- **Domain-wide delegation scope:** Broad domain-wide delegation is used for simplicity. In high-sensitivity environments, consider restricting delegation to specific OUs to reduce blast radius.

---

## Related Projects

**[scim-sanity](https://github.com/thomaselliottbetz/scim-sanity)** — SCIM server conformance testing tool that validates endpoints against RFC 7643/7644. Covers the provisioning layer that this project builds on: use scim-sanity to verify your SCIM endpoint is spec-compliant before relying on it for user provisioning into Entra ID or Google Workspace.

---

## Note on OAuth Scopes

In production, consider restricting service account impersonation to specific Organizational Units rather than using broad domain-wide delegation. This limits the blast radius if credentials are compromised and provides finer-grained access control in line with the Principle of Least Privilege.
