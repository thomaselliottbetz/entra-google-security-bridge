# Entra ID & Google Workspace Security Bridge

**Repository:** [thomaselliottbetz/entra-google-security-bridge](https://github.com/thomaselliottbetz/entra-google-security-bridge)

**Target Environment:** Microsoft Entra ID + Google Workspace (Hybrid Identity)

## Project Overview

This repository bridges security operations and attribute synchronization between Microsoft Entra ID and Google Workspace. While SCIM handles initial user provisioning, these scripts address ongoing security monitoring and post-provisioning attribute sync needs.

The project is organized into three functional domains: Identity Governance (Entra ID), Post-Provisioning Sync (Cross-Platform), and Collaboration Security (Google Workspace).

### 1. Identity Governance (Entra ID)

**Risky Sign-In Monitoring:** Programmatically detects suspicious sign-in patterns including "Impossible Travel" and "Anonymous IP" alerts from Microsoft's Identity Protection service. Microsoft's backend continuously analyzes sign-in patterns and flags suspicious activity, and this endpoint lets us query those flagged events programmatically to build our own security monitoring and alerting. Reports include user email, risk level (low/medium/high), IP address, geographic location (city, country), and specific risk event types that triggered the alert (like "anonymousIP" for VPN/Tor usage or "unfamiliarLocation" for sign-ins from new places).

**Performance Note:** Optimized via OData filtering on indexed `createdDateTime` fields to avoid API latency and 429 throttling. The query filters by time window only, since all results from the `riskySignIns` endpoint already have risk events associated. Results are filtered by risk level threshold in Python for optimal performance.

**Guest User Audit (Zero-Trust):** Flags stale or untrusted external identities (B2B users) that may need access review or revocation. Guest users are external identities invited to access organization resources, identified by the `userType` property set to "Guest" in Microsoft Graph API. The script categorizes guests by trust level (trusted vs untrusted domains) and activity status (based on last sign-in date) to help prioritize access reviews and removals for zero-trust compliance.

**Licensing Requirement:** Note that `lastSignInDateTime` is an Entra ID P1/P2 (Premium) property. The script handles cases where this property may be unavailable (e.g., standard tenants) by treating users without a last sign-in date as inactive.

**Tech Stack:** msal, Microsoft Graph API, OData

### 2. Post-Provisioning Sync (Cross-Platform)

**Attribute-Based OU Sync:** Queries Entra ID to identify users whose attributes have changed (e.g., Department, officeLocation) and synchronizes their Organizational Unit placement in Google Workspace. Assumes users already exist in Google Workspace (provisioned via SCIM or other means). Uses OData filter syntax supported by Microsoft Graph API (e.g., `officeLocation eq 'Seattle'` or `department eq 'Engineering'`) to find users needing OU updates. The returned user data includes key attributes like userPrincipalName (email), displayName, officeLocation, department, and jobTitle that can be used to update the user's organizational unit placement in Google Workspace.

**OAuth 2.0 Implementation:** Uses MSAL (Microsoft Authentication Library) for OAuth 2.0 client credentials flow with automatic token management.

**Tech Stack:** OAuth 2.0, Service Accounts, Domain-Wide Delegation

### 3. Collaboration Security (Google Workspace)

**OU Management:** Tools for rapid user relocation during role changes or incident response scenarios. Organizational units structure the organization's hierarchy and can apply different policies to different groups of users. Useful for reorganizing users as they change roles or departments. Suitable for scheduled execution, manual runs during user onboarding/offboarding, or integration into HR workflow automation.

**Shadow IT Audit:** Scans for high-risk OAuth tokens (e.g., `drive.readonly`, `gmail.send`) and flags apps not on the approved whitelist. Addresses the  "shadow IT" problem where users grant permissions without fully understanding the scope of access, allowing unauthorized third-party applications to gain access to corporate data. Each token represents an authorized application and includes what permissions (scopes) it has been granted, as well as whether it's an anonymous application. The output categorizes tokens into different risk levels: high-risk (blocked scopes, not approved), medium-risk (sensitive scopes but from unknown apps), and low-risk (approved apps or safe scopes). This helps prioritize which OAuth authorizations need immediate review or revocation. Handles pagination to support organizations with thousands of users.

**Tech Stack:** Google Admin SDK, Google Auth Library

## File Structure

- `identity_governance_ms.py` - Identity governance scripts for Microsoft ecosystem (risky sign-ins, guest user audit, post-provisioning sync source)
- `collaboration_security_google.py` - Collaboration security scripts for Google Workspace (OU management, OAuth token audit)

All functions include complete error handling and logging suitable for production use.

## Requirements

### Python Dependencies

```
msal>=1.24.0
google-auth>=2.23.0
google-api-python-client>=2.100.0
requests>=2.31.0
```

### Authentication Setup

**Entra ID:**
- App registration in Azure AD with appropriate API permissions
- Client ID and Client Secret
- Tenant ID

**Google Workspace:**
- Service account with domain-wide delegation enabled
- Service account JSON key file
- Admin user email for impersonation (set via `GOOGLE_ADMIN_EMAIL` environment variable)
- **Note:** `GOOGLE_ADMIN_EMAIL` is required and validated at runtime. If not set, functions will raise a `ValueError` with a clear error message.

### Required API Permissions

**Microsoft Graph:**
- `IdentityRiskEvent.Read.All` (for risky sign-ins)
- `User.Read.All` (for user queries)
- `Directory.Read.All` (for guest user audit)

**Google Workspace:**
- `admin.directory.user` (for OU management)
- `admin.directory.user.readonly` (for user listing)
- `admin.directory.user.security` (for OAuth token access - requires explicit admin approval)

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
    target_ou_path="/Engineering/Arene_Project",
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

### Post-Provisioning Sync: Query Entra ID for OU Updates

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
    email_domain_mapping={"@company.com": "@company.google.com"}  # Optional if domains differ
)

# Returns a dictionary with keys: 'synced', 'skipped', 'failed'
print(f"Synced: {len(result['synced'])} users")
print(f"Skipped (not in Google): {len(result['skipped'])} users")
print(f"Failed: {len(result['failed'])} users")

# Access details of synced users
for user in result['synced']:
    print(f"{user['email']} moved from {user['previous_ou']} to {user['target_ou']}")
```

## Production-Ready Considerations

These scripts incorporate infrastructure patterns suitable for enterprise deployment:

**API Resilience:** Built-in handling for `@odata.nextLink` (Microsoft) and `nextPageToken` (Google) to support environments with 10,000+ users. All user queries handle pagination automatically.

**Idempotency & Pre-flight Checks:** Functions verify the current state (e.g., current OU) before applying changes to prevent "blind updates" and unnecessary API overhead. This helps catch cases where the user might already be in a different OU than expected, which could indicate a data inconsistency or that the move was already performed.

**Principle of Least Privilege:** Scripts use granular scopes (e.g., `admin.directory.user.security`) rather than global Super Admin rights. Each function requests only the minimum permissions required.

**Structured Logging:** Ready for SIEM/SOAR integration (Splunk, Google SecOps, Microsoft Sentinel) via Python's logging module. All output uses appropriate log levels (INFO for general status, WARNING for security findings like risky sign-ins or untrusted guests, ERROR for failures) instead of print statements. This provides actionable information for security teams to investigate potential threats.

**Performance Optimization:** Complex array filtering is handled in Python rather than OData lambda operators to ensure highest performance during high-traffic security events. Time-based queries use indexed fields for optimal response times.

**Portability:** Using the `my_customer` alias and environment-based admin impersonation ensures the code is tenant-agnostic and ready for multi-region deployment.

## Deployment Options

Scripts can be run as:
- Scheduled jobs (cron, Task Scheduler)
- Python scheduled tasks (using the `schedule` library)
- Event-driven workflows (triggered by security alerts)
- Integrated into monitoring dashboards
- Manual execution for incident response

## Why This Approach Matters

**Security Monitoring:** These scripts provide programmatic access to security events (risky sign-ins, guest audits, OAuth token audits) that can be integrated into security workflows and monitoring systems.

**Post-Provisioning Sync:** While SCIM handles initial user provisioning, these scripts bridge the gap for ongoing attribute synchronization, particularly for organizational unit placement based on changing user attributes.

**Operational Efficiency:** By handling complex filtering in Python rather than OData lambda operators, we ensure optimal performance during high-traffic security events. Pagination handling ensures complete coverage even in large organizations.

## Note on OAuth Scopes

In a production environment, use Service Account Impersonation restricted by Organizational Unit rather than broad domain-wide delegation where possible, following the Principle of Least Privilege. This would limit the service account's scope to specific OUs, reducing the blast radius if credentials are compromised and providing finer-grained access control.

