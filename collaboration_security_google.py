# Security operations automation
# ============================================================================
# Google Workspace security scripts using Admin SDK API
# ELLIPTICAL VERSIONS - Essential implementations
# ============================================================================
import logging
import os

from google.oauth2 import service_account
from googleapiclient.discovery import build

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def move_user_to_ou(user_email, target_ou_path, credentials_path):
    """
    Moves a user to a different organizational unit (OU) in Google Workspace. Organizational
    units structure the organization's hierarchy and can apply different policies to different
    groups of users. Uses service account credentials with domain-wide delegation enabled,
    which allows the service account to act on behalf of users in the domain. We impersonate
    an admin user via with_subject() method using the GOOGLE_ADMIN_EMAIL environment variable,
    then use Admin SDK Directory API to update the user's orgUnitPath property. This is useful
    for reorganizing users as they change roles or departments. Suitable for scheduled execution,
    manual runs during user onboarding/offboarding, or integration into HR workflow automation.
    """
    
    # Service account setup (assumes domain-wide delegation configured)
    creds = service_account.Credentials.from_service_account_file(
        credentials_path,
        scopes=['https://www.googleapis.com/auth/admin.directory.user']
    )
    delegated = creds.with_subject(os.environ.get('GOOGLE_ADMIN_EMAIL'))
    
    service = build('admin', 'directory_v1', credentials=delegated)
    service.users().update(
        userKey=user_email,
        body={"orgUnitPath": target_ou_path}
    ).execute()
    
    logger.info(f"Moved {user_email} to {target_ou_path}")

def audit_oauth_tokens(credentials_path, blocked_scopes=None, approved_apps=None):
    """
    Audit third-party OAuth apps users have authorized to access Google Workspace data. Users
    often grant permissions without fully understanding what access they're providing, creating
    "shadow IT" - unauthorized third-party applications with access to corporate data. This
    uses Google Admin SDK with broader permissions (admin.directory.user.readonly and
    admin.directory.user.security scopes) to query the tokens() API endpoint for all users.
    Handles pagination to retrieve all users in large organizations. Each token represents
    an authorized application and includes what permissions (scopes) it has been granted.
    Checks tokens against blocked_scopes list and approved_apps whitelist, flags high-risk
    apps (blocked scopes + not approved) to help reduce attack surface. Run as a scheduled
    audit, on-demand, or integrated into a monitoring system.
    """
    
    # Broader scopes needed for token access
    creds = service_account.Credentials.from_service_account_file(
        credentials_path,
        scopes=[
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
            'https://www.googleapis.com/auth/admin.directory.user.security'
        ]
    )
    delegated = creds.with_subject(os.environ.get('GOOGLE_ADMIN_EMAIL'))
    service = build('admin', 'directory_v1', credentials=delegated)
    
    blocked_scopes = blocked_scopes or ['https://www.googleapis.com/auth/drive']
    approved_apps = approved_apps or []
    
    # Get all users and their tokens (handle pagination)
    users = []
    page_token = None
    while True:
        if page_token:
            result = service.users().list(customer='my_customer', maxResults=500, pageToken=page_token).execute()
        else:
            result = service.users().list(customer='my_customer', maxResults=500).execute()
        users.extend(result.get('users', []))
        page_token = result.get('nextPageToken')
        if not page_token:
            break
    
    high_risk = []
    
    for user in users:
        email = user.get('primaryEmail')
        if not email:
            continue
        try:
            tokens = service.tokens().list(userKey=email).execute().get('items', [])
            for token in tokens:
                app_name = token.get('displayText', 'Unknown')
                scopes = token.get('scopes', [])
                has_blocked = any(s in blocked_scopes for s in scopes)
                is_approved = any(a.lower() in app_name.lower() for a in approved_apps)
                
                if has_blocked and not is_approved:
                    high_risk.append({'user': email, 'app': app_name, 'scopes': scopes})
        except Exception:
            # User may not have tokens or we may lack permission - skip
            continue
    
    # Report findings
    for item in high_risk:
        logger.warning(f"HIGH RISK FOUND: {item['user']} | {item['app']} | {item['scopes']}")
    
    return high_risk

# ============================================================================
# FULL IMPLEMENTATIONS - Detailed versions with complete error handling
# ============================================================================

import os

from google.oauth2 import service_account
from googleapiclient.discovery import build

def move_user_between_ous(user_email, source_org_unit_path, target_org_unit_path, credentials_path):
    """
    Moves users between organizational units (OUs) in Google Workspace, which is useful for
    reorganizing users as they change roles or departments. Organizational units help structure
    the organization's hierarchy and can be used to apply different policies to different
    groups of users.
    
    The function starts by loading service account credentials from a JSON file specified by
    credentials_path. These credentials need to have domain-wide delegation enabled, which
    allows the service account to act on behalf of users in the domain. We request the
    admin.directory.user scope, which gives us permission to read and update user information.
    
    Since we're using a service account, we need to impersonate an admin user to perform the
    operation. This is done using the with_subject() method, which takes the admin email from
    the GOOGLE_ADMIN_EMAIL environment variable. The delegated_credentials object now has the
    authority to act as that admin user.
    
    We then build the Admin SDK Directory API service using discovery.build(). Before making
    the change, we optionally verify the user's current OU by calling users().get() to fetch
    the user's current information. This helps catch cases where the user might already be in
    a different OU than expected, which could indicate a data inconsistency or that the move
    was already performed.
    
    To move the user, we create an update_body dictionary with the new orgUnitPath and call
    users().update() with the user's email as the userKey. The API updates the user's
    organizational unit, which can affect what policies and settings apply to that user. This
    is particularly important in security contexts where different OUs might have different
    security requirements or access controls.
    """
    # Create credentials
    scopes = ['https://www.googleapis.com/auth/admin.directory.user']
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=scopes)
    
    # Needs domain-wide delegation - use admin user for impersonation
    delegated_credentials = credentials.with_subject(os.environ.get('GOOGLE_ADMIN_EMAIL'))

    service = build('admin', 'directory_v1', credentials=delegated_credentials)
    try:
        # Optionally: verify user's current OU (uncomment for audit)
        user = service.users().get(userKey=user_email).execute()
        current_ou = user.get('orgUnitPath', '')
        if current_ou != source_org_unit_path:
            logger.warning(f"User OU is '{current_ou}', not expected '{source_org_unit_path}'. Proceeding.")

        body = {
            "orgUnitPath": target_org_unit_path
        }
        service.users().update(userKey=user_email, body=body).execute()
        logger.info(f"User {user_email} moved to {target_org_unit_path}.")
    except Exception as e:
        logger.error(f"Error moving user: {e}")

# Example usage (variables should be set accordingly)
# os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@yourdomain.com'
# move_user_between_ous(
#     user_email="user@example.com",
#     source_org_unit_path="/OldOrgUnit",
#     target_org_unit_path="/NewOrgUnit",
#     credentials_path="/path/to/service_account.json"
# )

def audit_oauth_tokens_full(credentials_path, blocked_scopes=None, approved_apps=None):
    """
    Audits third-party applications that users have authorized to access their Google Workspace
    data through OAuth tokens. Users sometimes grant permissions without fully understanding
    the scope of access, allowing unauthorized third-party applications to gain access to
    corporate data.
    
    The authentication setup uses service account credentials with domain-wide delegation.
    We request both admin.directory.user.readonly (to list users) and admin.directory.user.security
    (to read OAuth token information). The security scope is particularly sensitive and requires
    explicit approval in the Google Workspace admin console.
    
    The script works by first retrieving a list of all users in the domain, handling pagination
    to support large organizations with thousands of users. For each user, we then query their
    OAuth tokens using the tokens() API endpoint. Each token represents an application that the
    user has authorized, and includes information about what permissions (scopes) that application
    has been granted. Common scopes include reading email, accessing Google Drive files, reading
    calendar information, etc.
    
    The blocked_scopes parameter allows us to define which permissions are considered high-risk.
    For example, we might block any application requesting drive.readonly scope unless it's from
    an approved vendor. The approved_apps parameter lets us maintain a whitelist.
    
    For each token found, we extract the client name (the application name), the scopes it has
    access to, and whether it's an anonymous application. We then check if any of the scopes are
    in the blocked list, and whether the application is in the approved list. Applications that
    have blocked scopes and aren't approved are flagged as high-risk.
    
    The output categorizes tokens into different risk levels using the logging system: high-risk
    (blocked scopes, not approved), medium-risk (sensitive scopes but from unknown apps), and
    low-risk (approved apps or safe scopes). This helps us prioritize which OAuth authorizations
    need immediate review or revocation, reducing the attack surface by removing unnecessary
    third-party access to corporate data.
    """
    # Create credentials with broader scopes for token access
    scopes = [
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
        'https://www.googleapis.com/auth/admin.directory.user.security'
    ]
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=scopes)
    
    # Use admin user for impersonation
    delegated_credentials = credentials.with_subject(os.environ.get('GOOGLE_ADMIN_EMAIL'))
    service = build('admin', 'directory_v1', credentials=delegated_credentials)
    
    if blocked_scopes is None:
        blocked_scopes = [
            'https://www.googleapis.com/auth/drive.readonly',
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send'
        ]
    
    if approved_apps is None:
        approved_apps = []
    
    try:
        # Get all users in the domain (handle pagination)
        users = []
        page_token = None
        
        while True:
            if page_token:
                users_result = service.users().list(
                    customer='my_customer', 
                    maxResults=500,
                    pageToken=page_token
                ).execute()
            else:
                users_result = service.users().list(
                    customer='my_customer', 
                    maxResults=500
                ).execute()
            
            page_users = users_result.get('users', [])
            users.extend(page_users)
            
            # Check if there are more pages
            page_token = users_result.get('nextPageToken')
            if not page_token:
                break
        
        high_risk_tokens = []
        medium_risk_tokens = []
        low_risk_tokens = []
        
        logger.info(f"Auditing OAuth tokens for {len(users)} users...")
        
        for user in users:
            user_email = user.get('primaryEmail')
            if not user_email:
                continue
            
            try:
                # Get OAuth tokens for this user
                tokens_result = service.tokens().list(userKey=user_email).execute()
                tokens = tokens_result.get('items', [])
                
                for token in tokens:
                    client_id = token.get('clientId', 'Unknown')
                    display_text = token.get('displayText', 'Unknown Application')
                    scopes = token.get('scopes', [])
                    anonymous = token.get('anonymous', False)
                    
                    # Check if any scopes are blocked
                    has_blocked_scope = any(scope in blocked_scopes for scope in scopes)
                    
                    # Check if app is approved
                    is_approved = any(approved in display_text.lower() or approved in client_id.lower() 
                                    for approved in approved_apps)
                    
                    token_info = {
                        'user': user_email,
                        'app_name': display_text,
                        'client_id': client_id,
                        'scopes': scopes,
                        'anonymous': anonymous
                    }
                    
                    # Categorize by risk
                    if has_blocked_scope and not is_approved:
                        high_risk_tokens.append(token_info)
                    elif has_blocked_scope or (scopes and not is_approved):
                        medium_risk_tokens.append(token_info)
                    else:
                        low_risk_tokens.append(token_info)
                        
            except Exception as e:
                # Some users might not have tokens or we might not have permission
                continue
        
        # Log results
        logger.info("OAuth Token Audit Results:")
        
        if high_risk_tokens:
            logger.warning(f"HIGH RISK ({len(high_risk_tokens)} tokens): These apps have blocked scopes and are not approved.")
            for token in high_risk_tokens:
                logger.warning(f"  User: {token['user']} | App: {token['app_name']} | Client ID: {token['client_id']}")
                logger.warning(f"  Blocked Scopes: {[s for s in token['scopes'] if s in blocked_scopes]}")
                if token['anonymous']:
                    logger.warning(f"  Anonymous application")
        
        if medium_risk_tokens:
            logger.info(f"MEDIUM RISK ({len(medium_risk_tokens)} tokens): These apps have sensitive permissions but may be legitimate.")
            for token in medium_risk_tokens[:10]:  # Show first 10
                logger.info(f"  User: {token['user']} | App: {token['app_name']}")
            if len(medium_risk_tokens) > 10:
                logger.info(f"  ... and {len(medium_risk_tokens) - 10} more")
        
        if low_risk_tokens:
            logger.info(f"LOW RISK ({len(low_risk_tokens)} tokens): These are approved apps or have safe permissions.")
        
        return {
            'high_risk': high_risk_tokens,
            'medium_risk': medium_risk_tokens,
            'low_risk': low_risk_tokens
        }
        
    except Exception as e:
        logger.error(f"Error auditing OAuth tokens: {e}")
        return {}

# Example usage for big-enterprise
# os.environ['GOOGLE_ADMIN_EMAIL'] = 'admin@bigenterprise.com'
# audit_oauth_tokens(
#     credentials_path="/path/to/service_account.json",
#     blocked_scopes=[
#         'https://www.googleapis.com/auth/drive',
#         'https://www.googleapis.com/auth/gmail.send'
#     ],
#     approved_apps=['Google Workspace', 'Slack', 'Microsoft']
# )

