import logging
import os

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from identity_governance_ms import build_user_filter, get_entra_users_with_changes

logger = logging.getLogger(__name__)


# Retries the Google client applies to each call on 429 and 5xx responses. OU updates set an
# absolute value, so repeating one is safe.
_API_RETRIES = 3

# Scopes that grant broad access to mail, files, or cloud resources. audit_oauth_tokens flags
# a token holding any of these unless its client ID is approved. A blocked_scopes argument
# replaces this list; extend it with [*DEFAULT_BLOCKED_SCOPES, ...] to keep the defaults.
DEFAULT_BLOCKED_SCOPES = (
    'https://mail.google.com/',  # full Gmail access: read, send, delete, IMAP/SMTP
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/cloud-platform',
)


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


class OUMismatchError(ValueError):
    """The user is not in the OU the caller expected; nothing was changed."""


def move_user_to_ou(user_email, target_ou_path, credentials_path, dry_run=False):
    """
    Moves a user to a different organizational unit in Google Workspace.

    Updates the user's orgUnitPath property using Google Admin SDK Directory API.
    Requires service account with domain-wide delegation and GOOGLE_ADMIN_EMAIL environment variable.

    Args:
        user_email: User's primary email address
        target_ou_path: Target organizational unit path (e.g., "/Engineering/Seattle")
        credentials_path: Path to service account JSON key file
        dry_run: If True, log the move that would be made and change nothing. No API call is
                 made, so the user's existence and the OU path are not checked.
    """
    scopes = ['https://www.googleapis.com/auth/admin.directory.user']
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=scopes)

    delegated_credentials = credentials.with_subject(_get_admin_email())
    service = build('admin', 'directory_v1', credentials=delegated_credentials)

    if dry_run:
        logger.info(f"[DRY RUN] Would move {user_email} to {target_ou_path}")
        return

    try:
        service.users().update(userKey=user_email, body={"orgUnitPath": target_ou_path}).execute(num_retries=_API_RETRIES)
        logger.info(f"User {user_email} moved to {target_ou_path}")
    except Exception as e:
        logger.error(f"Error moving user: {e}")
        raise


def move_user_between_ous(user_email, source_org_unit_path, target_org_unit_path, credentials_path, dry_run=False):
    """
    Moves a user between organizational units in Google Workspace with pre-flight verification.

    Reads the user's current OU and moves them only if it matches the expected source OU.
    On a mismatch nothing is changed and ValueError is raised. The read and the update are
    separate API calls, so this narrows the window for a stale move but is not atomic.

    Args:
        user_email: User's primary email address
        source_org_unit_path: Expected current OU path (for verification)
        target_org_unit_path: Target OU path
        credentials_path: Path to service account JSON key file
        dry_run: If True, perform the read and the source check but skip the update. A source
                 mismatch still raises, so a dry run shows what a real run would refuse.

    Raises:
        OUMismatchError: (a ValueError) If the user's current OU differs from source_org_unit_path.
                         It is not logged as an error.

    Note: Requires service account with domain-wide delegation and GOOGLE_ADMIN_EMAIL environment variable.
    """
    scopes = ['https://www.googleapis.com/auth/admin.directory.user']
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=scopes)

    delegated_credentials = credentials.with_subject(_get_admin_email())
    service = build('admin', 'directory_v1', credentials=delegated_credentials)

    try:
        user = service.users().get(userKey=user_email).execute(num_retries=_API_RETRIES)
        current_ou = user.get('orgUnitPath', '')
        if current_ou != source_org_unit_path:
            raise OUMismatchError(
                f"User {user_email} is in '{current_ou}', not expected '{source_org_unit_path}'; not moved."
            )

        if dry_run:
            logger.info(f"[DRY RUN] Would move {user_email} from {current_ou} to {target_org_unit_path}")
            return

        service.users().update(userKey=user_email, body={"orgUnitPath": target_org_unit_path}).execute(num_retries=_API_RETRIES)
        logger.info(f"User {user_email} moved to {target_org_unit_path}.")
    except OUMismatchError:
        raise  # a refused pre-flight is the guard working; the caller gets the message, not an ERROR log
    except Exception as e:
        logger.error(f"Error moving user: {e}")
        raise


def audit_oauth_tokens(credentials_path, blocked_scopes=None, approved_apps=None):
    """
    Audits third-party OAuth tokens granted by users in Google Workspace.

    Scans all users for authorized OAuth applications, categorizing each token by risk level
    based on the scopes granted and whether the application is in the approved list. Handles
    pagination to support large organizations.

    Args:
        credentials_path: Path to service account JSON key file
        blocked_scopes: List of OAuth scope URIs considered high-risk (default:
                        DEFAULT_BLOCKED_SCOPES: full and partial Gmail access, Drive, and
                        cloud-platform). Replaces the defaults rather than extending them.
        approved_apps: OAuth client IDs of approved applications (default: none). Accepts any
                       iterable of client IDs, or a dict of {client_id: label}. Matching is an
                       exact, case-insensitive comparison on client ID only; display names are
                       attacker-controlled and are never used for approval.

    Returns:
        Dictionary with keys 'high_risk', 'medium_risk', 'low_risk', 'errors'. The risk keys
        contain lists of token dictionaries with user, app_name, client_id, scopes, and
        anonymous fields. 'anonymous' is informational: it reports that the app has an
        anonymous client ID (not registered with Google) and does not change the risk tier,
        which depends only on scopes and the approved list. 'errors' lists users whose tokens could not be retrieved
        (user, error), i.e. coverage gaps in the audit. If the audit fails as a whole (for
        example, listing users), the four keys are still returned, empty except for a single
        'errors' entry with user None, and no summary event is emitted; an empty result with
        no errors is a genuinely clean audit. Credential and GOOGLE_ADMIN_EMAIL problems raise
        instead of returning.

    Note: Requires service account with domain-wide delegation and GOOGLE_ADMIN_EMAIL environment
    variable. Each scope used here must be authorized for the service account's client ID in the
    Google Workspace admin console (domain-wide delegation). admin.directory.user.security is
    the most sensitive of them: it covers application-specific password, OAuth token, and
    verification code operations, not only token listing.
    """
    admin_scopes = [
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
        'https://www.googleapis.com/auth/admin.directory.user.security'
    ]
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path, scopes=admin_scopes)

    delegated_credentials = credentials.with_subject(_get_admin_email())
    service = build('admin', 'directory_v1', credentials=delegated_credentials)

    if blocked_scopes is None:
        blocked_scopes = DEFAULT_BLOCKED_SCOPES
    blocked_scopes = set(blocked_scopes)

    approved_client_ids = {str(c).lower() for c in (approved_apps or [])}

    try:
        users = []
        page_token = None

        while True:
            kwargs = {'customer': 'my_customer', 'maxResults': 500}
            if page_token:
                kwargs['pageToken'] = page_token
            users_result = service.users().list(**kwargs).execute(num_retries=_API_RETRIES)
            users.extend(users_result.get('users', []))
            page_token = users_result.get('nextPageToken')
            if not page_token:
                break

        high_risk_tokens = []
        medium_risk_tokens = []
        low_risk_tokens = []
        errors = []

        logger.info(f"Auditing OAuth tokens for {len(users)} users...")

        for user in users:
            user_email = user.get('primaryEmail')
            if not user_email:
                continue

            try:
                tokens_result = service.tokens().list(userKey=user_email).execute(num_retries=_API_RETRIES)
                tokens = tokens_result.get('items', [])

                for token in tokens:
                    client_id = token.get('clientId', 'Unknown')
                    display_text = token.get('displayText', 'Unknown Application')
                    token_scopes = token.get('scopes', [])
                    anonymous = token.get('anonymous', False)

                    has_blocked_scope = any(scope in blocked_scopes for scope in token_scopes)
                    is_approved = client_id.lower() in approved_client_ids

                    token_info = {
                        'user': user_email,
                        'app_name': display_text,
                        'client_id': client_id,
                        'scopes': token_scopes,
                        'anonymous': anonymous
                    }

                    if has_blocked_scope and not is_approved:
                        high_risk_tokens.append(token_info)
                    elif has_blocked_scope or (token_scopes and not is_approved):
                        medium_risk_tokens.append(token_info)
                    else:
                        low_risk_tokens.append(token_info)

            except Exception as e:
                logger.warning(
                    f"Could not retrieve tokens for {user_email}; user not audited: {e}",
                    extra={"event": "oauth_token_fetch_failed", "user": user_email, "error": str(e)},
                )
                errors.append({'user': user_email, 'error': str(e)})
                continue

        audited = sum(1 for u in users if u.get('primaryEmail')) - len(errors)
        logger.info(
            "OAuth Token Audit Results:",
            extra={
                "event": "oauth_audit_summary",
                "users_audited": audited,
                "users_total": audited + len(errors),
                "users_failed": len(errors),
                "high_risk": len(high_risk_tokens),
                "medium_risk": len(medium_risk_tokens),
                "low_risk": len(low_risk_tokens),
            },
        )
        if errors:
            logger.warning(
                f"COVERAGE GAP: audited {audited} of {audited + len(errors)} users; "
                f"{len(errors)} could not be audited.",
                extra={
                    "event": "oauth_audit_coverage_gap",
                    "users_audited": audited,
                    "users_total": audited + len(errors),
                    "users_failed": len(errors),
                },
            )

        if high_risk_tokens:
            logger.warning(f"HIGH RISK ({len(high_risk_tokens)} tokens): These apps have blocked scopes and are not approved.")
            for token in high_risk_tokens:
                token_blocked = [s for s in token['scopes'] if s in blocked_scopes]
                logger.warning(
                    f"  User: {token['user']} | App: {token['app_name']} | Client ID: {token['client_id']} | "
                    f"Blocked Scopes: {token_blocked}" + (" | Anonymous application" if token['anonymous'] else ""),
                    extra={
                        "event": "oauth_high_risk_token",
                        "user": token['user'],
                        "app_name": token['app_name'],
                        "client_id": token['client_id'],
                        "blocked_scopes": token_blocked,
                        "anonymous": token['anonymous'],
                    },
                )

        if medium_risk_tokens:
            logger.info(f"MEDIUM RISK ({len(medium_risk_tokens)} tokens): Approved apps holding blocked scopes, or unapproved apps with other scopes.")
            # Text output shows the first 10; JSON output carries every token (json_only).
            for i, token in enumerate(medium_risk_tokens):
                logger.info(
                    f"  User: {token['user']} | App: {token['app_name']}",
                    extra={
                        "event": "oauth_medium_risk_token",
                        "user": token['user'],
                        "app_name": token['app_name'],
                        "client_id": token['client_id'],
                        "scopes": token['scopes'],
                        "anonymous": token['anonymous'],
                        "json_only": i >= 10,
                    },
                )
            if len(medium_risk_tokens) > 10:
                logger.info(f"  ... and {len(medium_risk_tokens) - 10} more", extra={"text_only": True})

        if low_risk_tokens:
            logger.info(f"LOW RISK ({len(low_risk_tokens)} tokens): Approved apps without blocked scopes, or tokens with no scopes.")

        return {
            'high_risk': high_risk_tokens,
            'medium_risk': medium_risk_tokens,
            'low_risk': low_risk_tokens,
            'errors': errors
        }

    except Exception as e:
        logger.error(
            f"Error auditing OAuth tokens: {e}",
            extra={"event": "oauth_audit_failed", "error": str(e)},
        )
        return {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'errors': [{'user': None, 'error': str(e)}]
        }


def ou_mapping_filter(ou_mapping):
    """
    Builds the Entra $filter that selects exactly the users an ou_mapping can place.

    One clause per mapped attribute value, joined with 'or', so every user returned matches
    some mapping key. Attributes must be ones build_user_filter accepts; Graph compares
    strings case-insensitively, which sync_entra_to_google_ou mirrors when it matches.

    Raises:
        ValueError: If the mapping is empty or names an attribute that cannot be filtered on.
    """
    if not ou_mapping:
        raise ValueError("ou_mapping is empty")
    return " or ".join(
        build_user_filter(attribute, list(value_map))
        for attribute, value_map in ou_mapping.items()
    )


def _casefolded_mapping(ou_mapping):
    """Returns {attribute: {value.casefold(): (value, ou)}}; rejects keys that differ only by case."""
    folded = {}
    for attribute, value_map in ou_mapping.items():
        entries = {}
        for value, ou in value_map.items():
            key = str(value).casefold()
            if key in entries:
                raise ValueError(
                    f"ou_mapping[{attribute!r}] has keys that differ only by case: "
                    f"{entries[key][0]!r} and {value!r}"
                )
            entries[key] = (value, ou)
        folded[attribute] = entries
    return folded


def sync_entra_to_google_ou(
    entra_tenant_id,
    entra_client_id,
    entra_client_secret,
    google_credentials_path,
    ou_mapping=None,
    filter_criteria=None,
    email_domain_mapping=None,
    dry_run=False
):
    """
    Syncs organizational unit placement from Entra ID to Google Workspace.

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
        filter_criteria: OData filter for Entra ID query (optional). When omitted, it is
                         derived from ou_mapping (see ou_mapping_filter), so every user returned
                         matches some mapping key. Mapping values are matched case-insensitively,
                         like Graph's eq.
        email_domain_mapping: Optional dict mapping Entra email domains to Google domains,
                             e.g., {"@company.com": "@company.google.com"}
        dry_run: If True, look users up and work out every move but change nothing. Moves that
                 would be made are reported under 'would_sync' instead of 'synced'.

    Returns:
        Dictionary with keys 'synced', 'skipped', 'failed', 'unmapped', 'unchanged',
        'would_sync'. 'synced' and 'would_sync' (dry run only; empty otherwise) contain
        dictionaries with email, source_attr, source_value, target_ou, previous_ou.
        'skipped' and 'unmapped' and 'unchanged' contain email lists; 'failed' contains error
        details. Each Entra user with a userPrincipalName lands in exactly one bucket: 'unmapped'
        users exist in Google but match no ou_mapping rule, 'unchanged' users are already in
        their target OU. 'skipped' holds only users Google reports as not found (HTTP 404); any
        other lookup error (403, 429 after retries, 5xx, network) is recorded in 'failed' with
        target_ou None, since the user's state is unknown. A non-empty 'unmapped' means the filter
        and mapping disagree and is logged as a WARNING (event ou_sync_unmapped).
    """
    empty_result = {'synced': [], 'skipped': [], 'failed': [], 'unmapped': [], 'unchanged': [], 'would_sync': []}

    if ou_mapping is None:
        ou_mapping = {
            "officeLocation": {
                "Seattle": "/Engineering/Seattle",
                "NYC": "/Engineering/NYC"
            }
        }

    folded_mapping = _casefolded_mapping(ou_mapping)
    if filter_criteria is None:
        filter_criteria = ou_mapping_filter(ou_mapping)

    entra_users = get_entra_users_with_changes(
        tenant_id=entra_tenant_id,
        client_id=entra_client_id,
        client_secret=entra_client_secret,
        filter_criteria=filter_criteria,
        extra_select=list(ou_mapping)  # the mapped attributes must come back, whatever the filter
    )

    if not entra_users:
        logger.info(
            "No users found in Entra ID matching criteria",
            extra={
                "event": "ou_sync_summary", "synced": 0, "skipped": 0, "failed": 0,
                "unmapped": 0, "unchanged": 0, "would_sync": 0, "dry_run": dry_run,
            },
        )
        return empty_result

    creds = service_account.Credentials.from_service_account_file(
        google_credentials_path,
        scopes=['https://www.googleapis.com/auth/admin.directory.user']
    )
    delegated = creds.with_subject(_get_admin_email())
    service = build('admin', 'directory_v1', credentials=delegated)

    synced_users = []
    skipped_users = []
    failed_users = []
    unmapped_users = []
    unchanged_users = []
    would_sync_users = []

    logger.info(f"Processing {len(entra_users)} users from Entra ID for OU sync")

    for user in entra_users:
        email = user.get('userPrincipalName')
        if not email:
            logger.debug(f"Skipping user with no userPrincipalName: {user}")
            continue

        google_email = email
        if email_domain_mapping:
            for entra_domain, google_domain in email_domain_mapping.items():
                if email.endswith(entra_domain):
                    google_email = email.replace(entra_domain, google_domain)
                    break

        try:
            google_user = service.users().get(userKey=google_email).execute(num_retries=_API_RETRIES)
            current_ou = google_user.get('orgUnitPath', '/')
        except Exception as e:
            if isinstance(e, HttpError) and e.resp.status == 404:
                logger.debug(f"User {google_email} not found in Google Workspace, skipping: {e}")
                skipped_users.append(google_email)
            else:
                logger.error(
                    f"Could not look up {google_email} in Google Workspace: {e}",
                    extra={"event": "ou_sync_failed", "user": google_email, "target_ou": None, "error": str(e)},
                )
                failed_users.append({'email': google_email, 'target_ou': None, 'error': str(e)})
            continue

        target_ou = None
        matched_attr = None
        matched_value = None

        for attr_name, entries in folded_mapping.items():
            user_value = user.get(attr_name) or ''
            match = entries.get(str(user_value).casefold()) if user_value else None
            if match:
                target_ou = match[1]
                matched_attr = attr_name
                matched_value = user_value
                break

        if not target_ou:
            logger.debug(f"No OU mapping found for {email} (attributes: {user})")
            unmapped_users.append(google_email)
            continue

        if current_ou == target_ou:
            logger.debug(f"User {email} already in target OU {target_ou}, skipping")
            unchanged_users.append(google_email)
            continue

        move = {
            'email': google_email,
            'source_attr': matched_attr,
            'source_value': matched_value,
            'target_ou': target_ou,
            'previous_ou': current_ou
        }

        if dry_run:
            would_sync_users.append(move)
            logger.info(
                f"[DRY RUN] Would sync {google_email} from {current_ou} to {target_ou} "
                f"(matched on {matched_attr}={matched_value})",
                extra={"event": "ou_sync_would_move", "user": google_email, "source_attr": matched_attr,
                       "source_value": matched_value, "target_ou": target_ou, "previous_ou": current_ou},
            )
            continue

        try:
            service.users().update(userKey=google_email, body={"orgUnitPath": target_ou}).execute(num_retries=_API_RETRIES)
            synced_users.append(move)
            logger.info(f"Synced {google_email} from {current_ou} to {target_ou} (matched on {matched_attr}={matched_value})")
        except Exception as e:
            logger.error(
                f"Failed to sync {google_email} to {target_ou}: {e}",
                extra={"event": "ou_sync_failed", "user": google_email, "target_ou": target_ou, "error": str(e)},
            )
            failed_users.append({'email': google_email, 'target_ou': target_ou, 'error': str(e)})

    logger.info(
        f"{'[DRY RUN] ' if dry_run else ''}Sync complete: {len(synced_users)} synced, "
        f"{len(would_sync_users)} would sync, {len(skipped_users)} skipped (not in Google), "
        f"{len(failed_users)} failed, {len(unmapped_users)} unmapped, {len(unchanged_users)} unchanged",
        extra={
            "event": "ou_sync_summary",
            "synced": len(synced_users),
            "skipped": len(skipped_users),
            "failed": len(failed_users),
            "unmapped": len(unmapped_users),
            "unchanged": len(unchanged_users),
            "would_sync": len(would_sync_users),
            "dry_run": dry_run,
        },
    )

    if skipped_users:
        logger.warning(
            f"{len(skipped_users)} users matched in Entra ID but were not found in Google Workspace "
            f"(not provisioned, deprovisioned on one side, or email_domain_mapping is wrong)"
        )

    if unmapped_users:
        logger.warning(
            f"{len(unmapped_users)} users matched the filter but no ou_mapping rule; the filter and "
            f"mapping disagree (omit filter_criteria to derive the filter from the mapping)",
            extra={"event": "ou_sync_unmapped", "count": len(unmapped_users)},
        )

    if failed_users:
        logger.warning(f"Failed to sync {len(failed_users)} users")
        for failed in failed_users:
            logger.warning(f"  {failed['email']} -> {failed['target_ou']}: {failed['error']}")

    return {
        'synced': synced_users,
        'skipped': skipped_users,
        'failed': failed_users,
        'unmapped': unmapped_users,
        'unchanged': unchanged_users,
        'would_sync': would_sync_users
    }
