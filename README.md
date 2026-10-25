# Entra ID & Google Workspace Security Bridge

**Repository:** [thomaselliottbetz/entra-google-security-bridge](https://github.com/thomaselliottbetz/entra-google-security-bridge)
**Target Environment:** Microsoft Entra ID + Google Workspace (cross-platform)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Functional Domains](#functional-domains)
- [File Structure](#file-structure)
- [Requirements](#requirements)
- [Authentication Setup](#authentication-setup)
- [Required API Permissions](#required-api-permissions)
- [Usage Examples](#usage-examples)
- [Testing](#testing)
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
│ • Risk detections   │              │ • OU sync                  │
│ • Guest user audit  │              │ • OAuth token audit        │
│ • User attr query   │              │ • OU management            │
└─────────────────────┘              └────────────────────────────┘
         │                                        │
         └─── JSON logs → log forwarder → SIEM ───┘
           (e.g., Splunk, Sentinel, Google SecOps)
```

---

## Functional Domains

### 1. Identity Governance (Entra ID)

**Risk Detection Monitoring**

Detects suspicious sign-in activity by querying Microsoft Entra ID Protection risk detections (`/identityProtection/riskDetections`). Each result is one risk detection and includes the user, risk level (low/medium/high), IP address, geographic location, and the risk event type that triggered it — for example, `anonymizedIPAddress` for anonymizing VPN/Tor use or `newCountry` for activity from a new country. A single sign-in can produce several detections, and offline detections such as `leakedCredentials` may carry no IP address or location. Requires `IdentityRiskEvent.Read.All` and an Entra ID P1/P2 license.

Risk level filtering is applied in Python after retrieval rather than via OData lambda operators. The time-window filter is applied server-side on `detectedDateTime` (when the risk was detected, which for offline detections can be later than the activity itself), and results are ordered newest first in Python because the endpoint documents `$filter` and `$select` only. Requests carry a timeout and retry on 429/503 responses, honoring `Retry-After` with capped exponential backoff. Full pagination via `@odata.nextLink` ensures no events are missed.

**Guest User Audit (Zero-Trust)**

Flags stale or untrusted external identities (B2B users) for access review or revocation. Guest users are identified by `userType eq 'Guest'` in Microsoft Graph and categorized by trust level (trusted vs. untrusted domains) and activity status (based on `signInActivity`: the last successful sign-in when available, since failed attempts would otherwise make a stale account look active, falling back to the later of interactive and non-interactive attempts for sign-ins recorded before December 2023), making it straightforward to prioritize removals for zero-trust compliance.

A guest's home domain is taken from `mail`, or recovered from the `#EXT#` UPN when `mail` is empty, since the text after `@` in a guest UPN is the host tenant rather than the guest's organization. Guests with no recorded sign-in count as inactive only once they are older than the inactivity window, so freshly invited guests aren't flagged.

Note: `signInActivity` requires `AuditLog.Read.All` and an Entra ID P1/P2 license. If either is missing, Graph typically rejects the request with a 403; the audit then logs the error and returns empty results. If the request succeeds but the property is omitted, the audit logs a warning and judges activity from `createdDateTime` alone.

**Tech Stack:** MSAL, Microsoft Graph API, OData

---

### 2. Post-Provisioning Sync (Cross-Platform)

**Attribute-Based OU Sync**

Queries Entra ID for users whose attributes (e.g., `department`, `officeLocation`) match a given OData filter, then synchronizes their Organizational Unit placement in Google Workspace. Assumes users already exist in Google Workspace, provisioned via SCIM or other means.

Authentication uses MSAL's OAuth 2.0 client credentials flow with automatic token management. The returned user data — `id`, `userPrincipalName`, `displayName`, `mail`, `officeLocation`, `department`, `jobTitle`, `employeeId` — drives the OU mapping logic on the Google side.

**Tech Stack:** OAuth 2.0, Service Accounts, Domain-Wide Delegation

---

### 3. Collaboration Security (Google Workspace)

**OU Management**

Provides tools for user relocation during role changes or incident response. Includes a simple move function (`move_user_to_ou`) and a pre-flight variant (`move_user_between_ous`) that raises `ValueError` and leaves the user in place when their current OU does not match the expected source. All three write functions (`move_user_to_ou`, `move_user_between_ous`, `sync_entra_to_google_ou`) take `dry_run=True`, which logs what would change and makes no update; for scheduled use, run with `dry_run=True` first and review the output before enabling real runs. `move_user_to_ou` makes no API call in a dry run, `move_user_between_ous` still reads the user and enforces the source check, and `sync_entra_to_google_ou` performs every lookup so its report shows the real outcome for each user. Suitable for scheduled execution, manual incident response, or HR workflow automation.

**Shadow IT / OAuth Token Audit**

Scans all users for high-risk OAuth grants (by default full Gmail access `https://mail.google.com/`, `gmail.modify`, `gmail.readonly`, `gmail.send`, `drive`, `drive.readonly`, and `cloud-platform`; see `DEFAULT_BLOCKED_SCOPES`) and flags applications not on the approved allowlist. The allowlist is matched on exact OAuth client ID, never on display name, since display names are attacker-controlled. Users whose tokens cannot be retrieved are logged at `WARNING` and returned under an `errors` key, so coverage gaps are visible. Each token record includes the application name, granted scopes, and whether the application is anonymous (not registered with Google). The anonymous flag is informational and does not change the risk tier, which depends only on the scopes and the allowlist. A `blocked_scopes` argument replaces the default list; extend it with `[*DEFAULT_BLOCKED_SCOPES, ...]` to keep the defaults. Results are categorized into high-risk (a blocked scope, and the app is not approved), medium-risk (an approved app holding a blocked scope, or an unapproved app with any other scopes), and low-risk (an approved app without blocked scopes, or a token with no scopes). Full pagination handles organizations with thousands of users.

**Tech Stack:** Google Admin SDK, Google Auth Library

---

## File Structure

| File | Description |
|------|-------------|
| `identity_governance_ms.py` | Risk detection monitoring, guest user audit, and Entra ID attribute query for post-provisioning sync |
| `collaboration_security_google.py` | Google Workspace OU management (`move_user_to_ou`, `move_user_between_ous`), OAuth token audit, and cross-platform OU sync |
| `bridge_cli.py` | Command-line entry point for scheduled runs (`risk-detections`, `guest-audit`, `oauth-audit`, `ou-sync`) with exit codes for schedulers |

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
| `IdentityRiskEvent.Read.All` | Risk detection monitoring |
| `User.Read.All` | User attribute queries and guest user audit |
| `AuditLog.Read.All` | Guest sign-in activity (`signInActivity`) |

All permissions require application-level grants with admin consent. `Directory.Read.All` is not required: Microsoft Graph accepts it for listing users, but it is broader than `User.Read.All`, which covers every call here.

### Google Workspace

Each scope must be authorized for the service account's client ID in the Admin console's domain-wide delegation settings; no scope here is exempt from that.

| Scope | Purpose |
|---|---|
| `admin.directory.user` | OU management (read/write) |
| `admin.directory.user.readonly` | User listing for OAuth token audit |
| `admin.directory.user.security` | OAuth token listing. Google describes this scope as covering all application-specific password, OAuth token, and verification code operations, so it is the most sensitive of the three; this is why it is requested separately, and why the audit uses its own service account (see [Note on OAuth Scopes](#note-on-oauth-scopes)) |

---

## Usage Examples

The modules do not configure logging when imported. In a script, call `configure_logging()` once at startup to get the plain-text or (with `BRIDGE_LOG_FORMAT=json`) JSON output described below; `bridge_cli.py` does this itself. Without it, Python's last-resort handler still prints `WARNING` and above (every security finding) to stderr, but not `INFO` status or summary lines. An application with its own logging setup should skip the call and attach the formatter and filters to its own handler (see Logging and SIEM/SOAR Forwarding).

```python
from identity_governance_ms import configure_logging

configure_logging()
```

### Monitor Risk Detections

```python
from identity_governance_ms import get_risk_detections

detections = get_risk_detections(
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
from collaboration_security_google import audit_oauth_tokens, DEFAULT_BLOCKED_SCOPES

os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@bigenterprise.com'

token_report = audit_oauth_tokens(
    credentials_path="/path/to/service_account.json",
    # Optional: replaces the defaults, so extend them to keep the built-in list
    blocked_scopes=[*DEFAULT_BLOCKED_SCOPES, 'https://www.googleapis.com/auth/admin.directory.user'],
    approved_apps={'1234567890-abc.apps.googleusercontent.com': 'Slack'}  # OAuth client IDs
)

# Returns a dictionary with keys: 'high_risk', 'medium_risk', 'low_risk', 'errors'
# ('errors' lists users whose tokens could not be retrieved)
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

`filter_criteria` is a raw OData expression passed to Graph as written. When the attribute or value comes from outside the code, build the expression with `build_user_filter`, which accepts only known user attributes, doubles single quotes, and rejects empty values and control characters (raising `ValueError`):

```python
from identity_governance_ms import build_user_filter, get_entra_users_with_changes

flt = build_user_filter("officeLocation", ["Seattle", "NYC"])
# "officeLocation eq 'Seattle' or officeLocation eq 'NYC'"
users = get_entra_users_with_changes(tenant_id, client_id, client_secret, filter_criteria=flt)
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
    email_domain_mapping={"@company.com": "@company.google.com"},  # optional
    dry_run=True  # report what would move without changing anything; omit or False to apply
)

# Returns a dictionary with keys: 'synced', 'skipped', 'failed', 'unmapped', 'unchanged', 'would_sync'
# (with dry_run=True, planned moves are in 'would_sync' and 'synced' stays empty)
print(f"Synced: {len(result['synced'])} users")
print(f"Skipped (not in Google): {len(result['skipped'])} users")
print(f"Failed: {len(result['failed'])} users")
print(f"Unmapped (no ou_mapping match): {len(result['unmapped'])} users")
print(f"Unchanged (already in target OU): {len(result['unchanged'])} users")

for user in result['would_sync']:
    print(f"{user['email']} would move from {user['previous_ou']} to {user['target_ou']}")

for user in result['synced']:
    print(f"{user['email']} moved from {user['previous_ou']} to {user['target_ou']}")
```

---

## Testing

The tests mock the Microsoft Graph and Google Admin SDK calls, so no tenant or credentials are needed:

```bash
pip install -r requirements.txt pytest
python -m pytest tests/
```

---

## Production-Ready Considerations

**API Resilience**
Full pagination via `@odata.nextLink` (Microsoft Graph) and `nextPageToken` (Google Admin SDK) ensures complete result sets in organizations with 10,000+ users (completeness, not speed; see the OAuth audit scale limitation below). Every Google Admin SDK call, reads and OU updates alike, retries up to three times on 429 and 5xx responses; OU updates set an absolute value, so a repeat is safe. Microsoft Graph calls retry on 429 and 503 as described above.

**Idempotency & Pre-flight Checks**
`move_user_between_ous` refuses to move a user whose current OU differs from the expected source (the check and the update are separate calls, so it is not atomic), and `sync_entra_to_google_ou` skips users who are already in the target OU or not found in Google Workspace (HTTP 404 only; other lookup errors are reported as failed), preventing blind updates and unnecessary API calls. `move_user_to_ou` is the unchecked variant and moves unconditionally.

**Principle of Least Privilege**
Each function requests only the minimum OAuth scopes it needs, and `admin.directory.user.security` is requested separately from general directory access. The enforced limit is the scope list authorized for the service account in the Admin console, not what the code requests, so separate service accounts for auditing and for moves are recommended (see [Note on OAuth Scopes](#note-on-oauth-scopes)).

**Logging and SIEM/SOAR Forwarding**
All output uses Python's `logging` module with consistent levels: `INFO` for status, `WARNING` for security findings and audit coverage gaps, `ERROR` for failures. Output is plain text by default. Setting `BRIDGE_LOG_FORMAT=json` switches to JSON lines (one object per record, on stderr) that a log forwarder can ship to Splunk, Google SecOps, Microsoft Sentinel, or any other SIEM without custom parsing:

```bash
BRIDGE_LOG_FORMAT=json python bridge_cli.py guest-audit 2>> bridge.jsonl   # or your own script that calls configure_logging()
```

Every record carries `timestamp` (UTC, ISO 8601), `level`, `logger`, and `message`. Each finding additionally carries a stable `event` key and event-specific fields; other status lines do not, so detection rules should filter on `event`. JSON output is complete: every medium-risk OAuth token is emitted as its own event, whereas text output shows only the first 10 followed by a count. Each audit run that completes also emits one `*_summary` event, including when it finds nothing, so a dashboard or alert can detect that a scheduled job has stopped running. A run that fails (for example, on authentication or an API error) logs an `ERROR` and emits no summary, so alert on a missing summary or on `ERROR` records. For example, for a job scheduled hourly, alert when no `risk_detection_summary` arrives within two hours; choose the threshold to fit each job's schedule:

| `event` | Fields |
|---|---|
| `risk_detection` | `user`, `risk_level`, `risk_state`, `time`, `ip_address`, `city`, `country`, `risk_events` |
| `guest_untrusted_inactive`, `guest_untrusted_active`, `guest_trusted_inactive` | `user`, `display_name`, `domain`, `last_sign_in`, `created_at` |
| `oauth_high_risk_token` | `user`, `app_name`, `client_id`, `blocked_scopes`, `anonymous` |
| `oauth_medium_risk_token` | `user`, `app_name`, `client_id`, `scopes`, `anonymous` |
| `oauth_token_fetch_failed` | `user`, `error` |
| `oauth_audit_failed` | `error` |
| `oauth_audit_coverage_gap` | `users_audited`, `users_total`, `users_failed` |
| `cli_failed` | `command` (`bridge_cli.py` only: the command raised an unexpected exception) |
| `ou_sync_would_move` | `user`, `source_attr`, `source_value`, `target_ou`, `previous_ou` (dry run only) |
| `ou_sync_failed` | `user`, `target_ou`, `error` |
| `risk_detection_summary` | `findings`, `hours_back`, `min_risk_level` |
| `guest_audit_summary` | `guests_total`, `days_inactive`, `trusted_active`, `trusted_inactive`, `untrusted_active`, `untrusted_inactive` |
| `oauth_audit_summary` | `users_audited`, `users_total`, `users_failed`, `high_risk`, `medium_risk`, `low_risk` |
| `ou_sync_summary` | `synced`, `skipped`, `failed`, `unmapped`, `unchanged`, `would_sync`, `dry_run` |

This is output designed for ingestion, not a packaged integration: the scripts ship no SIEM connectors, schemas, or dashboards. `configure_logging()` is explicit and, like `logging.basicConfig`, does nothing if the root logger already has handlers; an application with its own logging setup can skip it and reuse the formatter and filters on its handler:

```python
from identity_governance_ms import JsonFormatter, ModeFilter

handler.setFormatter(JsonFormatter())
handler.addFilter(ModeFilter("text_only"))   # drop human-readable framing such as "... and N more"
# For a plain-text handler, use ModeFilter("json_only") instead to keep the 10-token truncation.
```

**Performance Optimization**
Complex filtering (e.g., risk level thresholds, domain matching) is applied in Python after retrieval rather than via OData lambda operators, which keeps behavior predictable on endpoints with limited OData support. Time-window filtering is applied server-side to limit the amount of data transferred.

**Portability**
The `my_customer` alias and environment-based admin impersonation keep the scripts tenant-agnostic and suitable for multi-region deployment.

---

## Deployment Options

`bridge_cli.py` is the entry point for scheduled runs:

```bash
export ENTRA_TENANT_ID=... ENTRA_CLIENT_ID=... ENTRA_CLIENT_SECRET=...   # from a secrets manager
export GOOGLE_CREDENTIALS_PATH=/etc/bridge/audit_sa.json GOOGLE_ADMIN_EMAIL=admin@example.com
export BRIDGE_LOG_FORMAT=json

python bridge_cli.py risk-detections --hours-back 1 --min-risk-level medium
python bridge_cli.py guest-audit --trusted-domain partner.com --days-inactive 90
python bridge_cli.py oauth-audit --approved-apps-file approved_apps.txt
python bridge_cli.py ou-sync --ou-mapping-file mapping.json --filter "officeLocation eq 'Seattle'"          # dry run
python bridge_cli.py ou-sync --ou-mapping-file mapping.json --filter "officeLocation eq 'Seattle'" --apply  # writes
```

Secrets are read from the environment, never from arguments, which are visible in process listings. Findings are written as log records (see Logging and SIEM/SOAR Forwarding under Production-Ready Considerations). `ou-sync` is a dry run unless `--apply` is given, and requires an explicit `--ou-mapping-file` and `--filter` rather than the library's example defaults. Subcommand options are listed with `--help`. `oauth-audit` extends the default blocked scopes with `--extra-blocked-scope`; the file form of the allowlist is one client ID per line, with `#` comments.

Exit codes let a scheduler tell the cases apart:

| Code | Meaning |
|---|---|
| 0 | The run completed. |
| 1 | The check reported findings and `--fail-on-findings` was given. |
| 2 | Usage or configuration error (missing setting, unreadable file). |
| 3 | The run failed or was incomplete: an `ERROR` was logged (for example an authentication failure), users could not be audited, or a sync update failed. Takes precedence over 1. |

Exit 3 matters because the library functions return empty results on failure; the CLI treats a logged `ERROR` as a failed run instead of a clean one. For `risk-detections` and `guest-audit`, findings are all returned detections and all guests except trusted-active; for `oauth-audit`, high-risk tokens.

Other ways to run it:

- Scheduled jobs (cron, Task Scheduler), for example the crontab entry `0 * * * * cd /opt/bridge && python bridge_cli.py risk-detections --hours-back 1`, with the environment variables above supplied by the scheduler or a wrapper that reads them from a secrets manager
- Python task schedulers (`schedule` library)
- Event-driven workflows triggered by security alerts
- Manual execution for incident response

---

## Limitations

- **Detection only:** These scripts report findings but do not perform automated remediation (e.g., revoking tokens, disabling accounts). Remediation is expected to be handled by downstream SOAR tooling or manual review.
- **Not real-time:** Queries are batch-oriented and designed for scheduled execution. For real-time event streaming, consider Microsoft Graph change notifications or Google Cloud Pub/Sub.
- **Requires existing provisioning:** `sync_entra_to_google_ou` assumes users already exist in Google Workspace. Initial provisioning is out of scope and expected to be handled via SCIM.
- **Entra ID P1/P2 required:** Both the risk detection API and `signInActivity` (used for guest inactivity checks) require premium licensing. On a non-premium tenant these queries are expected to fail with an error (logged) rather than produce results.
- **OAuth audit scale:** `audit_oauth_tokens` calls `tokens.list` once per user, serially, so run time grows with the number of users and can be long in organizations with tens of thousands of them (not benchmarked); a user whose call fails after retries is reported under `errors`, not skipped silently. The usual way to scale this is the Admin SDK Reports API, where `activities.list` with `applicationName=token` returns OAuth token events (`authorize`, `revoke`, `request`, `deny`, `activity`) for all users in pages, with `client_id`, `app_name` and `scope` on each event. That is an event log, not a snapshot of the grants that exist today. The documented default window is the most recent 180 days, so an older grant appears only if it has an event inside the window, and it needs the separate `admin.reports.audit.readonly` scope. It would suit continuous monitoring of new grants, and `tokens.list` remains the way to inventory current ones. Neither the Reports path nor any parallelism of the per-user calls is implemented here.
- **Long-lived secrets:** Entra authentication uses a client secret and Google authentication uses a downloadable service account JSON key; both are long-lived credentials that must be stored and rotated. Neither is the strongest option. For Entra, certificate credentials or federated credentials (workload identity federation) avoid a shared secret. For Google, domain-wide delegation does not require a downloadable key: Google's [domain-wide delegation best practices](https://support.google.com/a/answer/14437356) point to the IAM Credentials `signJwt` API instead and advise restricting key creation with organization policy. The scripts do not implement these options; `_get_graph_headers` accepts only a client secret and the Google functions load a key file.
- **Domain-wide delegation is broad:** The scripts authenticate with domain-wide delegation, which lets the service account impersonate any user in the domain and cannot be restricted to specific OUs. A leaked key carries the full reach of the scopes authorized for it in the Admin console; using separate service accounts for auditing and for moves limits that. See [Note on OAuth Scopes](#note-on-oauth-scopes).

---

## Related Projects

**[scim-sanity](https://github.com/thomaselliottbetz/scim-sanity)** — SCIM server conformance testing tool that validates endpoints against RFC 7643/7644. Covers the provisioning layer that this project builds on: use scim-sanity to verify your SCIM endpoint is spec-compliant before relying on it for user provisioning into Entra ID or Google Workspace.

---

## Note on OAuth Scopes

Domain-wide delegation lets the service account impersonate any user in the domain. It cannot be limited to specific Organizational Units, and the role of the admin named in `GOOGLE_ADMIN_EMAIL` does not bound it, because a holder of the key can name a different subject.

What does limit a leaked key is the scope list authorized for the service account's client ID in the Admin console (Security > Access and data control > API controls > Domain-wide delegation). A key holder can request any scope on that list, whatever the scripts themselves ask for, so the scopes requested in code are not a control; the console entry is. Keep it to what the scripts use, and protect the key: store it in a secrets manager, restrict who can read it, and rotate it.

**Separate service accounts per privilege tier.** Each function takes its own `credentials_path`, so the two tiers can use different service accounts, each with its own client ID and its own delegation entry:

| Service account | Functions | Scopes to authorize |
|---|---|---|
| Audit | `audit_oauth_tokens` | `admin.directory.user.readonly`, `admin.directory.user.security` |
| Move / sync | `move_user_to_ou`, `move_user_between_ous`, `sync_entra_to_google_ou` | `admin.directory.user` |

A leaked audit key can read users and enumerate OAuth tokens but cannot move users; a leaked move/sync key can modify users but cannot read tokens. This narrows what a stolen key can do, not whose accounts it can act on: each key can still impersonate any user for its authorized scopes.

**Direct role assignment (not implemented).** Google documents assigning a prebuilt or custom admin role, other than Super Admin, directly to a service account, with Directory API user creation as its example; this would avoid delegation for the user operations. The scripts do not support it, since they always impersonate `GOOGLE_ADMIN_EMAIL`, and it has not been verified that the `admin.directory.user.security` token endpoint works this way.
