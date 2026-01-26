import logging
from datetime import datetime, timedelta

import requests
from msal import ConfidentialClientApplication

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_risky_sign_ins(tenant_id, client_id, client_secret, hours_back=24, min_risk_level='medium'):
    """
    Queries Entra ID Identity Protection API for risky sign-in events with detailed error handling.
    
    Returns sign-ins flagged by Microsoft's risk detection within the specified time window.
    Filters by minimum risk level and logs detailed information for security investigation.
    
    Args:
        tenant_id: Entra ID tenant ID
        client_id: App registration client ID
        client_secret: App registration client secret
        hours_back: Time window in hours (default: 24)
        min_risk_level: Minimum risk level to include ('low', 'medium', 'high', default: 'medium')
    
    Returns:
        List of risky sign-in event dictionaries. Each includes userPrincipalName, riskLevel,
        riskState, createdDateTime, ipAddress, location (city, countryOrRegion), and
        riskEventTypes.
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

def audit_guest_users(tenant_id, client_id, client_secret, trusted_domains=None, days_inactive=90):
    """
    Audits external guest users (B2B) in Entra ID with detailed categorization.
    
    Queries all guest users and categorizes by trust level (trusted vs untrusted domains) and
    activity status (based on last sign-in date). Returns structured results for access review.
    
    Args:
        tenant_id: Entra ID tenant ID
        client_id: App registration client ID
        client_secret: App registration client secret
        trusted_domains: List of trusted external domains (default: None)
        days_inactive: Days since last sign-in to consider inactive (default: 90)
    
    Returns:
        Dictionary with keys: 'trusted_active', 'trusted_inactive', 'untrusted_active',
        'untrusted_inactive'. Each contains lists of guest user dictionaries with email,
        display_name, domain, last_sign_in, created, external_user_state.
    
    Note: Requires User.Read.All or Directory.Read.All application permission with admin consent.
    lastSignInDateTime requires Entra ID P1/P2 license.
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

def get_entra_users_with_changes(tenant_id, client_id, client_secret, filter_criteria=None):
    """
    Queries Entra ID for users matching filter criteria with detailed error handling.
    
    Returns user attributes for post-provisioning attribute synchronization. Handles pagination
    and provides summary statistics on retrieved users.
    
    Args:
        tenant_id: Entra ID tenant ID
        client_id: App registration client ID
        client_secret: App registration client secret
        filter_criteria: OData filter expression (default: "officeLocation eq 'Seattle'")
    
    Returns:
        List of user dictionaries with id, userPrincipalName, displayName, mail, officeLocation,
        department, jobTitle, employeeId.
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

