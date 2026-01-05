# Hybrid Identity & Security Automation Suite

**Repository:** [thomaselliottbetz/entra-google-security-bridge](https://github.com/thomaselliottbetz/entra-google-security-bridge)

**Target Environment:** Microsoft Entra ID + Google Workspace (Hybrid Identity)

## Project Overview

This suite provides an end-to-end framework for managing security and identity lifecycle across a hybrid enterprise environment. It bridges the gap between Entra ID (Primary IdP) and Google Workspace (Collaboration Layer), ensuring security policies and user placements remain synchronized in real-time.

The project is organized into three functional domains that create an automated security response loop: Identity Governance (Entra ID), The SSO Bridge (Cross-Platform), and Collaboration Security (Google Workspace).

### 1. Identity Governance (Entra ID)

**Risky Sign-In Monitoring:** Programmatically detects suspicious sign-in patterns including "Impossible Travel" and "Anonymous IP" alerts from Microsoft's Identity Protection service. Microsoft's backend continuously analyzes sign-in patterns and flags suspicious activity, and this endpoint lets us query those flagged events programmatically to build our own security monitoring and alerting. Reports include user email, risk level (low/medium/high), IP address, geographic location (city, country), and specific risk event types that triggered the alert (like "anonymousIP" for VPN/Tor usage or "unfamiliarLocation" for sign-ins from new places).

**Performance Note:** Optimized via OData filtering on indexed `createdDateTime` fields to avoid API latency and 429 throttling. The query filters by time window only, since all results from the `riskySignIns` endpoint already have risk events associated. Results are filtered by risk level threshold in Python for optimal performance.

**Guest User Audit (Zero-Trust):** Flags stale or untrusted external identities (B2B users) that may need access review or revocation. Guest users are external identities invited to access organization resources, identified by the `userType` property set to "Guest" in Microsoft Graph API. The script categorizes guests by trust level (trusted vs untrusted domains) and activity status (based on last sign-in date) to help prioritize access reviews and removals for zero-trust compliance.

**Licensing Requirement:** Note that `lastSignInDateTime` is an Entra ID P1/P2 (Premium) property; the script includes fallback logic for standard tenants.

**Tech Stack:** msal, Microsoft Graph API, OData

### 2. The SSO Bridge (Cross-Platform)

**Automated Provisioning:** Uses Entra ID as the "Source of Truth" to drive Organizational Unit (OU) placement in Google Workspace. When a new engineer is hired, they are created in Entra ID first, then this function queries Entra ID to find users who need to be provisioned or moved in Google Workspace based on specific attributes (e.g., Department, officeLocation, or custom attributes). Uses OData filter syntax supported by Microsoft Graph API (e.g., `officeLocation eq 'Seattle'` or `department eq 'Engineering'`). The returned user data includes key attributes like userPrincipalName (email), displayName, officeLocation, department, and jobTitle that can be used by a separate provisioning script to synchronize the user's organizational unit, department, and other attributes.

**OAuth 2.0 Implementation:** Includes both "Elliptical" implementations using raw `v2.0/token` requests with the `.default` scope to illustrate the essential Client Credentials Grant flow, and full implementations using MSAL for production use.

**Tech Stack:** OAuth 2.0, Service Accounts, Domain-Wide Delegation

### 3. Collaboration Security (Google Workspace)

**OU Management:** Tools for rapid user relocation during role changes or incident response scenarios. Organizational units structure the organization's hierarchy and can apply different policies to different groups of users. Useful for reorganizing users as they change roles or departments. Suitable for scheduled execution, manual runs during user onboarding/offboarding, or integration into HR workflow automation.

**Shadow IT Audit:** Scans for high-risk OAuth tokens (e.g., `drive.readonly`, `gmail.send`) and flags apps not on the approved whitelist. Addresses the  "shadow IT" problem where users grant permissions without fully understanding the scope of access, allowing unauthorized third-party applications to gain access to corporate data. Each token represents an authorized application and includes what permissions (scopes) it has been granted, as well as whether it's an anonymous application. The output categorizes tokens into different risk levels: high-risk (blocked scopes, not approved), medium-risk (sensitive scopes but from unknown apps), and low-risk (approved apps or safe scopes). This helps prioritize which OAuth authorizations need immediate review or revocation. Handles pagination to support organizations with thousands of users.

**Tech Stack:** Google Admin SDK, Google Auth Library

## File Structure

- `identity_governance_ms.py` - Identity governance scripts for Microsoft ecosystem (risky sign-ins, guest user audit, SSO bridge source)
- `collaboration_security_google.py` - Collaboration security scripts for Google Workspace (OU management, OAuth token audit)

Each file contains both "Elliptical" versions (concise implementations) and "Full" versions (production-ready with complete error handling).

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

audit_oauth_tokens(
    credentials_path="/path/to/service_account.json",
    blocked_scopes=[
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/gmail.send'
    ],
    approved_apps=['Google Workspace', 'Slack', 'Microsoft']
)
```

### SSO Bridge: Query Entra ID for Provisioning

```python
from identity_governance_ms import get_entra_users_with_changes

users_to_provision = get_entra_users_with_changes(
    tenant_id="your-tenant-id",
    client_id="your-app-client-id",
    client_secret="your-client-secret",
    filter_criteria="officeLocation eq 'Seattle' or department eq 'Engineering'"
)
```

## Production-Ready Considerations

This suite incorporates infrastructure patterns required for enterprise-scale deployment:

**API Resilience:** Built-in handling for `@odata.nextLink` (Microsoft) and `nextPageToken` (Google) to support environments with 10,000+ users. All user queries handle pagination automatically.

**Idempotency & Pre-flight Checks:** Full implementations verify the current state (e.g., current OU) before applying changes to prevent "blind updates" and unnecessary API overhead. This helps catch cases where the user might already be in a different OU than expected, which could indicate a data inconsistency or that the move was already performed.

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

**Defense-in-Depth:** We don't just detect risk; we automate the mitigation (moving OUs) and the forensics (auditing tokens). The SSO bridge ensures identity changes in Entra ID are automatically reflected in Google Workspace.

**Efficiency:** By handling complex filtering in Python rather than OData lambda operators, we ensure the highest performance during high-traffic security events. Pagination handling ensures complete coverage even in large organizations.

**Portability:** Using tenant-agnostic patterns and environment-based configuration ensures the code works across different tenants and regions without modification.

## Note on OAuth Scopes

In a production environment, use Service Account Impersonation restricted by Organizational Unit rather than broad domain-wide delegation where possible, following the Principle of Least Privilege. This would limit the service account's scope to specific OUs, reducing the blast radius if credentials are compromised and providing finer-grained access control.

