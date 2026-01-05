# Security operations automation
# ============================================================================
# Entra ID security scripts using Microsoft Graph API
# ELLIPTICAL VERSIONS - Essential implementations
# ============================================================================
import logging
from datetime import datetime, timedelta

import requests
from msal import ConfidentialClientApplication

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_risky_sign_ins(tenant_id, client_id, client_secret, hours_back=24, min_risk_level='medium'):
    """
    Suspicious Entra sign-ins. This endpoint is part of Microsoft Graph API's Identity Protection
    service. Microsoft's backend continuously analyzes sign-in patterns and flags suspicious
    activity - things like sign-ins from anonymous IPs, unfamiliar locations, or impossible travel
    patterns. This endpoint lets us query those flagged events programmatically so we can build
    our own security monitoring and alerting on top of it. The MSAL authentication library handles
    OAuth flow for MS Graph API access then queries the Identity Protection API for risky events
    within hours_back window, filters by risk level, and reports IP, locations, and risk event
    types. Can be scheduled via cron, run on-demand, integrated into monitoring dashboards, or
    triggered by security events.
    """
    # Authentication setup (simplified - assumes proper app registration exists)
    
    app = ConfidentialClientApplication(client_id, client_credential=client_secret,
                                      authority=f"https://login.microsoftonline.com/{tenant_id}")
    token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    
    if "access_token" not in token:
        return []
    
    # Query risky sign-ins from last N hours
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    start_time = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + "Z"
    
    response = requests.get(
        "https://graph.microsoft.com/v1.0/identityProtection/riskySignIns",
        headers=headers,
        params={"$filter": f"createdDateTime ge {start_time}", "$top": 100}
    ).json()
    
    # Filter by risk level threshold
    risk_map = {"low": 0, "medium": 1, "high": 2}
    min_level = risk_map.get(min_risk_level.lower(), 1)
    
    filtered = [s for s in response.get("value", []) 
                if risk_map.get(s.get("riskLevel", "low").lower(), 0) >= min_level]
    
    # Log results
    for sign_in in filtered:
        loc = sign_in.get("location", {})
        logger.warning(f"RISKY SIGN-IN: {sign_in.get('userPrincipalName')} | {sign_in.get('riskLevel')} | "
                      f"{sign_in.get('ipAddress')} | {loc.get('city')}, {loc.get('countryOrRegion')} | "
                      f"{', '.join(sign_in.get('riskEventTypes', []))}")
    
    return filtered

def audit_guest_users(tenant_id, client_id, client_secret, trusted_domains=None, days_inactive=90):
    """
    Audit external guest users (B2B) in Entra ID. Guest users are external identities invited
    to access organization resources - they're identified by userType property set to "Guest"
    in Microsoft Graph API. Over time these can accumulate or become stale, creating an
    expanded attack surface. This queries the Users endpoint, filters for guest users, and
    categorizes them by trust level (trusted vs untrusted domains) and activity status (based
    on last sign-in date). Helps prioritize access reviews and removals for zero-trust
    compliance.
    """
    # Authentication (same pattern as above)
    
    app = ConfidentialClientApplication(client_id, client_credential=client_secret,
                                      authority=f"https://login.microsoftonline.com/{tenant_id}")
    token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    
    if "access_token" not in token:
        return []
    
    # Get all guest users
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    guests = requests.get(
        "https://graph.microsoft.com/v1.0/users",
        headers=headers,
        params={"$filter": "userType eq 'Guest'"}
    ).json().get("value", [])
    
    # Categorize by trust and activity
    cutoff = datetime.utcnow() - timedelta(days=days_inactive)
    trusted_domains = trusted_domains or []
    
    for guest in guests:
        email = guest.get("userPrincipalName", "")
        domain = email.split("@")[-1] if "@" in email else ""
        last_signin = guest.get("lastSignInDateTime")
        
        is_trusted = any(td.lower() in domain.lower() for td in trusted_domains)
        is_active = last_signin and datetime.fromisoformat(last_signin.replace("Z", "+00:00")) > cutoff
        
        status = "WARNING" if not is_trusted else "OK"
        activity = "INACTIVE" if not is_active else "active"
        if not is_trusted:
            logger.warning(f"UNTRUSTED GUEST: {email} ({domain}) - {activity} - Last: {last_signin or 'Never'}")
        else:
            logger.info(f"Trusted guest: {email} ({domain}) - {activity} - Last: {last_signin or 'Never'}")
    
    return guests

def get_entra_users_with_changes(tenant_id, client_id, client_secret, filter_criteria=None):
    """
    SSO bridge source side - reads from Entra ID. When a new engineer is hired, they are
    created in Entra ID first. This function queries Entra ID to find users who need to be
    provisioned or moved in Google Workspace based on specific attributes (e.g., Department,
    officeLocation, or custom attributes). Uses Microsoft Graph API with OAuth client credentials
    flow. Handles pagination to retrieve all matching users. Can be run as part of a provisioning
    sync workflow or scheduled job.
    """
    
    # Get OAuth token for Entra ID
    auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    auth_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }
    
    try:
        token_response = requests.post(auth_url, data=auth_data)
        token_response.raise_for_status()
        token = token_response.json().get('access_token')
        
        if not token:
            logger.error("Failed to obtain access token")
            return []
        
        headers = {'Authorization': f'Bearer {token}'}
        
        # Build query with filter (example: find Seattle office users)
        if filter_criteria is None:
            filter_criteria = "officeLocation eq 'Seattle'"
        
        query_url = f"https://graph.microsoft.com/v1.0/users?$filter={filter_criteria}&$select=id,userPrincipalName,displayName,officeLocation,department,jobTitle"
        
        # Handle pagination
        all_users = []
        page_url = query_url
        
        while page_url:
            response = requests.get(page_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            all_users.extend(data.get('value', []))
            
            # Check for next page
            page_url = data.get('@odata.nextLink')
        
        logger.info(f"Found {len(all_users)} users matching criteria: {filter_criteria}")
        return all_users
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying Entra ID users: {e}")
        return []

# ============================================================================
# FULL IMPLEMENTATIONS - Detailed versions with complete error handling
# ============================================================================

from datetime import datetime, timedelta
from msal import ConfidentialClientApplication
import requests

def get_risky_sign_ins_full(tenant_id, client_id, client_secret, hours_back=24, min_risk_level='medium'):
    """
    Monitors Entra ID for suspicious sign-in activity that could indicate compromised accounts
    or unauthorized access attempts. Works by authenticating to Microsoft Graph API using the
    tenant_id, client_id, and client_secret parameters, then queries the Identity Protection
    service for risky sign-in events.
    
    The authentication flow starts by creating a ConfidentialClientApplication object
    with the provided credentials. We call acquire_token_for_client() with the
    "https://graph.microsoft.com/.default" scope to get an access token that allows
    us to read Identity Protection data.
    
    Once authenticated, we calculate a time window using the hours_back parameter
    (defaulting to 24 hours). The start_time and end_time variables define this window,
    and we format start_time_str in ISO 8601 format for the API.
    
    We then make a GET request to the Identity Protection API endpoint, filtering for
    sign-ins within our time window. Since we're querying the riskySignIns endpoint,
    all returned results already have risk events associated with them. The response
    contains a list of risky_sign_ins, each with details like the user's email
    (userPrincipalName), risk level (low/medium/high), IP address, geographic location,
    and specific risk event types that triggered the alert (like "anonymousIP" for VPN/Tor
    usage or "unfamiliarLocation" for sign-ins from new places).
    
    We filter these results based on min_risk_level - we compare each sign-in's risk level
    against our threshold using the risk_level_map dictionary. Only sign-ins meeting or
    exceeding the minimum risk level are included in filtered_sign_ins.
    
    Finally, we iterate through filtered_sign_ins and log the key details using the
    logging system: who signed in, when, from where (IP and location), what risk level
    was assigned, and what specific events triggered the alert. This gives security teams
    actionable information to investigate potential threats.
    """
    # Authenticate to Microsoft Graph
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )
    
    scopes = ["https://graph.microsoft.com/.default"]
    result = app.acquire_token_for_client(scopes=scopes)
    
    if "access_token" not in result:
        logger.error(f"Authentication failed: {result.get('error_description')}")
        return []
    
    access_token = result["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Calculate time window
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours_back)
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # Query risky sign-ins
    graph_url = "https://graph.microsoft.com/v1.0/identityProtection/riskySignIns"
    params = {
        "$filter": f"createdDateTime ge {start_time_str}",
        "$orderby": "createdDateTime desc",
        "$top": 100
    }
    
    try:
        response = requests.get(graph_url, headers=headers, params=params)
        response.raise_for_status()
        risky_sign_ins = response.json().get("value", [])
        
        # Filter by risk level
        risk_level_map = {"low": 0, "medium": 1, "high": 2}
        min_level = risk_level_map.get(min_risk_level.lower(), 1)
        
        filtered_sign_ins = []
        for sign_in in risky_sign_ins:
            risk_level = sign_in.get("riskLevel", "unknown")
            risk_level_value = risk_level_map.get(risk_level.lower(), 0)
            
            if risk_level_value >= min_level:
                filtered_sign_ins.append(sign_in)
        
        # Log results
        if not filtered_sign_ins:
            logger.info(f"No risky sign-ins found in the last {hours_back} hours (minimum risk: {min_risk_level})")
            return []
        
        logger.warning(f"Found {len(filtered_sign_ins)} risky sign-in(s) in the last {hours_back} hours:")
        
        for sign_in in filtered_sign_ins:
            user_principal_name = sign_in.get("userPrincipalName", "Unknown")
            risk_level = sign_in.get("riskLevel", "Unknown")
            risk_state = sign_in.get("riskState", "Unknown")
            created_time = sign_in.get("createdDateTime", "Unknown")
            ip_address = sign_in.get("ipAddress", "Unknown")
            location = sign_in.get("location", {})
            city = location.get("city", "Unknown")
            country = location.get("countryOrRegion", "Unknown")
            risk_event_types = sign_in.get("riskEventTypes", [])
            
            logger.warning(f"User: {user_principal_name} | Risk Level: {risk_level.upper()} | "
                          f"Risk State: {risk_state} | Time: {created_time} | "
                          f"IP: {ip_address} | Location: {city}, {country} | "
                          f"Risk Events: {', '.join(risk_event_types) if risk_event_types else 'None'}")
        
        return filtered_sign_ins
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying risky sign-ins: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return []

# Example usage for big-enterprise
# get_risky_sign_ins(
#     tenant_id="your-tenant-id",
#     client_id="your-app-client-id",
#     client_secret="your-client-secret",
#     hours_back=24,
#     min_risk_level="medium"
# )

def audit_guest_users_full(tenant_id, client_id, client_secret, trusted_domains=None, days_inactive=90):
    """
    Audits external guest users (B2B users) in Entra ID to identify potential security risks
    from third-party access. Guest users are external identities that have been invited to
    access the organization's resources, and over time these can accumulate or become stale,
    creating an expanded attack surface.
    
    The script starts by authenticating to Microsoft Graph API using the same MSAL pattern as
    the risky sign-ins script. We use ConfidentialClientApplication to get an access token with
    permissions to read user directory information.
    
    Once authenticated, we query the Users endpoint and filter for guest users. In Entra ID,
    guest users are identified by the userType property being set to "Guest". We retrieve all
    guest users and examine their properties, particularly focusing on their email domains to see
    if they're from trusted partner organizations or unknown external domains.
    
    The trusted_domains parameter allows us to specify which external domains are considered safe
    (like partner companies). Any guest users from domains not in this list are flagged as
    potentially risky. We also check the last sign-in date for each guest user - if a guest hasn't
    signed in for more than days_inactive (default 90 days), they're considered stale and may
    need their access reviewed or revoked.
    
    For each guest user, we extract their userPrincipalName, display name, the domain they're
    from, their last sign-in date, and what groups or applications they have access to. The
    script then categorizes guests into different risk categories: trusted active users, trusted
    but inactive, untrusted active, and untrusted inactive. This helps security teams prioritize
    which guest accounts need immediate attention.
    
    The output provides a clear report showing which external users have access, when they last
    used that access, and whether they're from known partner organizations. This supports a
    zero-trust approach by ensuring we have visibility into all external access and can enforce
    least-privilege principles by removing access for users who no longer need it.
    """
    # Authenticate to Microsoft Graph
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )
    
    scopes = ["https://graph.microsoft.com/.default"]
    result = app.acquire_token_for_client(scopes=scopes)
    
    if "access_token" not in result:
        logger.error(f"Authentication failed: {result.get('error_description')}")
        return []
    
    access_token = result["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Query all guest users
    graph_url = "https://graph.microsoft.com/v1.0/users"
    params = {
        "$filter": "userType eq 'Guest'",
        "$select": "id,userPrincipalName,displayName,mail,userType,externalUserState,createdDateTime,lastSignInDateTime"
    }
    
    if trusted_domains is None:
        trusted_domains = []
    
    try:
        response = requests.get(graph_url, headers=headers, params=params)
        response.raise_for_status()
        guest_users = response.json().get("value", [])
        
        if not guest_users:
            logger.info("No guest users found in the directory.")
            return []
        
        # Calculate cutoff date for inactive users
        cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
        
        # Categorize guest users
        trusted_active = []
        trusted_inactive = []
        untrusted_active = []
        untrusted_inactive = []
        
        for guest in guest_users:
            email = guest.get("userPrincipalName", guest.get("mail", "Unknown"))
            domain = email.split("@")[-1] if "@" in email else "Unknown"
            last_sign_in = guest.get("lastSignInDateTime")
            display_name = guest.get("displayName", "Unknown")
            created = guest.get("createdDateTime", "Unknown")
            
            # Check if domain is trusted
            is_trusted = any(trusted_domain.lower() in domain.lower() for trusted_domain in trusted_domains) if trusted_domains else False
            
            # Check if user is inactive
            is_inactive = True
            if last_sign_in:
                try:
                    last_sign_in_date = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
                    is_inactive = last_sign_in_date < cutoff_date
                except (ValueError, AttributeError):
                    # Invalid date format or missing date - treat as inactive
                    pass
            
            guest_info = {
                "email": email,
                "display_name": display_name,
                "domain": domain,
                "last_sign_in": last_sign_in or "Never",
                "created": created,
                "external_user_state": guest.get("externalUserState", "Unknown")
            }
            
            if is_trusted:
                if is_inactive:
                    trusted_inactive.append(guest_info)
                else:
                    trusted_active.append(guest_info)
            else:
                if is_inactive:
                    untrusted_inactive.append(guest_info)
                else:
                    untrusted_active.append(guest_info)
        
        # Log results
        logger.info(f"Guest User Audit Report - Total guest users: {len(guest_users)}, Inactive threshold: {days_inactive} days")
        
        if untrusted_inactive:
            logger.warning(f"UNTRUSTED INACTIVE ({len(untrusted_inactive)}):")
            for guest in untrusted_inactive:
                logger.warning(f"  {guest['email']} ({guest['display_name']}) | "
                             f"Domain: {guest['domain']} | Last sign-in: {guest['last_sign_in']} | Created: {guest['created']}")
        
        if untrusted_active:
            logger.warning(f"UNTRUSTED ACTIVE ({len(untrusted_active)}):")
            for guest in untrusted_active:
                logger.warning(f"  {guest['email']} ({guest['display_name']}) | "
                             f"Domain: {guest['domain']} | Last sign-in: {guest['last_sign_in']}")
        
        if trusted_inactive:
            logger.info(f"Trusted but Inactive ({len(trusted_inactive)}):")
            for guest in trusted_inactive:
                logger.info(f"  {guest['email']} ({guest['display_name']}) | Last sign-in: {guest['last_sign_in']}")
        
        if trusted_active:
            logger.info(f"Trusted Active ({len(trusted_active)}): These are from trusted domains and have recent activity")
        
        return {
            "trusted_active": trusted_active,
            "trusted_inactive": trusted_inactive,
            "untrusted_active": untrusted_active,
            "untrusted_inactive": untrusted_inactive
        }
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying guest users: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return []

# Example usage for big-enterprise
# audit_guest_users(
#     tenant_id="your-tenant-id",
#     client_id="your-app-client-id",
#     client_secret="your-client-secret",
#     trusted_domains=["bigenterprise.com", "partner-company.com"],
#     days_inactive=90
# )

def get_entra_users_with_changes_full(tenant_id, client_id, client_secret, filter_criteria=None):
    """
    Demonstrates the 'Source' side of the SSO bridge for provisioning users from Entra ID into
    Google Workspace. When a new engineer is hired, they are created in Entra ID first. This
    script then queries Entra ID to find users who have specific attributes that trigger a Google
    Workspace provisioning or organizational unit move.
    
    The function uses Microsoft Graph API with OAuth 2.0 client credentials flow. We use MSAL
    (Microsoft Authentication Library) to handle the authentication, which provides a cleaner
    interface than raw HTTP requests. The ConfidentialClientApplication class manages the token
    acquisition and refresh automatically.
    
    The filter_criteria parameter allows us to specify which users to retrieve. For example, we
    might filter by officeLocation to find all Seattle office users, or by department to find all
    Engineering team members. The function uses OData filter syntax supported by Microsoft Graph
    API.
    
    The script handles pagination automatically by checking for the @odata.nextLink property in
    the API response. This ensures we retrieve all matching users, not just the first page, which
    is critical for large organizations with thousands of employees.
    
    The returned user data includes key attributes like userPrincipalName (email), displayName,
    officeLocation, department, and jobTitle. This information can then be used by a separate
    provisioning script to create or update the corresponding user in Google Workspace, ensuring
    the user's organizational unit, department, and other attributes are synchronized.
    
    This is part of a larger SSO bridge architecture where Entra ID serves as the source of truth
    for user identity, and Google Workspace is provisioned based on Entra ID attributes.
    """
    from msal import ConfidentialClientApplication
    import requests
    
    # Authenticate to Microsoft Graph using MSAL
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )
    
    scopes = ["https://graph.microsoft.com/.default"]
    result = app.acquire_token_for_client(scopes=scopes)
    
    if "access_token" not in result:
        logger.error(f"Authentication failed: {result.get('error_description')}")
        return []
    
    access_token = result["access_token"]
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        
        # Build query with filter (default: find Seattle office users as example)
        if filter_criteria is None:
            filter_criteria = "officeLocation eq 'Seattle'"
        
        # Select specific user attributes needed for provisioning
        select_fields = "id,userPrincipalName,displayName,mail,officeLocation,department,jobTitle,employeeId"
        query_url = f"https://graph.microsoft.com/v1.0/users?$filter={filter_criteria}&$select={select_fields}"
        
        # Handle pagination to get all matching users
        all_users = []
        page_url = query_url
        
        while page_url:
            response = requests.get(page_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            page_users = data.get('value', [])
            all_users.extend(page_users)
            
            logger.debug(f"Retrieved {len(page_users)} users from current page")
            
            # Check for next page using @odata.nextLink
            page_url = data.get('@odata.nextLink')
        
        logger.info(f"Found {len(all_users)} users matching criteria: {filter_criteria}")
        
        # Log summary of retrieved users
        if all_users:
            locations = {}
            departments = {}
            for user in all_users:
                loc = user.get('officeLocation', 'Unknown')
                dept = user.get('department', 'Unknown')
                locations[loc] = locations.get(loc, 0) + 1
                departments[dept] = departments.get(dept, 0) + 1
            
            logger.info(f"User distribution - Locations: {locations}, Departments: {departments}")
        
        return all_users
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying Entra ID users: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return []

# Example usage for big-enterprise
# get_entra_users_with_changes(
#     tenant_id="your-tenant-id",
#     client_id="your-app-client-id",
#     client_secret="your-client-secret",
#     filter_criteria="officeLocation eq 'Seattle' or department eq 'Engineering'"
# )

