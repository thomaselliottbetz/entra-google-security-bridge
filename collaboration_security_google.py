import logging
import os

from google.oauth2 import service_account
from googleapiclient.discovery import build
from identity_governance_ms import get_entra_users_with_changes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _get_admin_email():
    """
    Gets and validates GOOGLE_ADMIN_EMAIL environment variable.
    
    Returns:
        Admin email address string
    
    Raises:
        ValueError: If GOOGLE_ADMIN_EMAIL is not set
    """
    admin_email = os.environ.get('GOOGLE_ADMIN_EMAIL')
    if not admin_email:
        raise ValueError("GOOGLE_ADMIN_EMAIL environment variable must be set")
    return admin_email

def move_user_to_ou(user_email, target_ou_path, credentials_path):
    """
    Moves a user to a different organizational unit in Google Workspace.
    
    Updates the user's orgUnitPath property using Google Admin SDK Directory API.
    Requires service account with domain-wide delegation and GOOGLE_ADMIN_EMAIL environment variable.
    
    Args:
        user_email: User's primary email address
        target_ou_path: Target organizational unit path (e.g., "/Engineering/Seattle")
        credentials_path: Path to service account JSON key file
    """
    scopes = ['https://www.googleapis.com/auth/admin.directory.user']
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=scopes)
    
    delegated_credentials = credentials.with_subject(_get_admin_email())
    service = build('admin', 'directory_v1', credentials=delegated_credentials)
    
    try:
        body = {"orgUnitPath": target_ou_path}
        service.users().update(userKey=user_email, body=body).execute()
        logger.info(f"User {user_email} moved to {target_ou_path}")
    except Exception as e:
        logger.error(f"Error moving user: {e}")
        raise

def move_user_between_ous(user_email, source_org_unit_path, target_org_unit_path, credentials_path):
    """
    Moves a user between organizational units in Google Workspace with pre-flight verification.
    
    Verifies the user's current OU matches the expected source OU before moving to target OU.
    Logs a warning if current OU differs from expected source.
    
    Args:
        user_email: User's primary email address
        source_org_unit_path: Expected current OU path (for verification)
        target_org_unit_path: Target OU path
        credentials_path: Path to service account JSON key file
    
    Note: Requires service account with domain-wide delegation and GOOGLE_ADMIN_EMAIL environment variable.
    """
    # Create credentials
    scopes = ['https://www.googleapis.com/auth/admin.directory.user']
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=scopes)
    
    # Needs domain-wide delegation - use admin user for impersonation
    delegated_credentials = credentials.with_subject(_get_admin_email())

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

def audit_oauth_tokens(credentials_path, blocked_scopes=None, approved_apps=None):
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
    delegated_credentials = credentials.with_subject(_get_admin_email())
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

def sync_entra_to_google_ou(
    entra_tenant_id,
    entra_client_id,
    entra_client_secret,
    google_credentials_path,
    ou_mapping=None,
    filter_criteria=None,
    email_domain_mapping=None
):
    """
    Syncs organizational unit placement from Entra ID to Google Workspace with detailed error handling.
    
    Queries Entra ID for users matching filter criteria, maps attributes to OU paths, and
    updates Google Workspace users. Verifies user existence, checks current OU, and provides
    detailed logging and error reporting.
    
    Args:
        entra_tenant_id: Entra ID tenant ID
        entra_client_id: Entra ID app client ID
        entra_client_secret: Entra ID app client secret
        google_credentials_path: Path to Google service account JSON
        ou_mapping: Dict mapping Entra attributes to OU paths, e.g.:
                   {"officeLocation": {"Seattle": "/Engineering/Seattle", "NYC": "/Engineering/NYC"}}
                   or {"department": {"Engineering": "/Engineering"}}
        filter_criteria: OData filter for Entra ID query (optional)
        email_domain_mapping: Optional dict mapping Entra email domains to Google domains,
                             e.g., {"@company.com": "@company.google.com"}
    
    Returns:
        Dictionary with keys 'synced', 'skipped', 'failed'. 'synced' contains dictionaries with
        email, source_attr, source_value, target_ou, previous_ou. 'skipped' and 'failed' contain
        email lists and error details respectively.
    """
    if ou_mapping is None:
        ou_mapping = {
            "officeLocation": {
                "Seattle": "/Engineering/Seattle",
                "NYC": "/Engineering/NYC"
            }
        }
    
    # Get users from Entra ID
    entra_users = get_entra_users_with_changes(
        tenant_id=entra_tenant_id,
        client_id=entra_client_id,
        client_secret=entra_client_secret,
        filter_criteria=filter_criteria
    )
    
    if not entra_users:
        logger.info("No users found in Entra ID matching criteria")
        return []
    
    # Setup Google service for checking user existence
    creds = service_account.Credentials.from_service_account_file(
        google_credentials_path,
        scopes=['https://www.googleapis.com/auth/admin.directory.user']
    )
    delegated = creds.with_subject(_get_admin_email())
    service = build('admin', 'directory_v1', credentials=delegated)
    
    synced_users = []
    skipped_users = []
    failed_users = []
    
    logger.info(f"Processing {len(entra_users)} users from Entra ID for OU sync")
    
    for user in entra_users:
        email = user.get('userPrincipalName')
        if not email:
            logger.debug(f"Skipping user with no userPrincipalName: {user}")
            continue
        
        # Transform email if domain mapping provided
        google_email = email
        if email_domain_mapping:
            for entra_domain, google_domain in email_domain_mapping.items():
                if email.endswith(entra_domain):
                    google_email = email.replace(entra_domain, google_domain)
                    break
        
        # Check if user exists in Google Workspace
        try:
            google_user = service.users().get(userKey=google_email).execute()
            current_ou = google_user.get('orgUnitPath', '/')
        except Exception as e:
            logger.debug(f"User {google_email} not found in Google Workspace, skipping: {e}")
            skipped_users.append(google_email)
            continue
        
        # Determine target OU based on mapping
        target_ou = None
        matched_attr = None
        matched_value = None
        
        for attr_name, value_map in ou_mapping.items():
            user_value = user.get(attr_name, '')
            if user_value and user_value in value_map:
                target_ou = value_map[user_value]
                matched_attr = attr_name
                matched_value = user_value
                break
        
        if not target_ou:
            logger.debug(f"No OU mapping found for {email} (attributes: {user})")
            continue
        
        # Skip if already in target OU
        if current_ou == target_ou:
            logger.debug(f"User {email} already in target OU {target_ou}, skipping")
            continue
        
        # Move user to target OU
        try:
            move_user_to_ou(
                user_email=google_email,
                target_ou_path=target_ou,
                credentials_path=google_credentials_path
            )
            synced_users.append({
                'email': google_email,
                'source_attr': matched_attr,
                'source_value': matched_value,
                'target_ou': target_ou,
                'previous_ou': current_ou
            })
            logger.info(f"Synced {google_email} from {current_ou} to {target_ou} (matched on {matched_attr}={matched_value})")
        except Exception as e:
            logger.error(f"Failed to sync {google_email} to {target_ou}: {e}")
            failed_users.append({'email': google_email, 'target_ou': target_ou, 'error': str(e)})
    
    # Summary logging
    logger.info(f"Sync complete: {len(synced_users)} synced, {len(skipped_users)} skipped (not in Google), {len(failed_users)} failed")
    
    if skipped_users:
        logger.info(f"Skipped users (not found in Google Workspace): {len(skipped_users)}")
    
    if failed_users:
        logger.warning(f"Failed to sync {len(failed_users)} users")
        for failed in failed_users:
            logger.warning(f"  {failed['email']} -> {failed['target_ou']}: {failed['error']}")
    
    return {
        'synced': synced_users,
        'skipped': skipped_users,
        'failed': failed_users
    }
