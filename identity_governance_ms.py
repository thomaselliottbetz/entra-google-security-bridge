import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests
from msal import ConfidentialClientApplication


class JsonFormatter(logging.Formatter):
    """
    Formats each log record as one JSON object per line, for SIEM/SOAR log forwarders.

    Emits timestamp (UTC, ISO 8601), level, logger, and message, plus any fields passed
    via logging's `extra=` (findings carry a stable 'event' key and event-specific fields).
    """

    _STANDARD_ATTRS = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
        "message", "asctime", "json_only", "text_only"
    }

    def format(self, record):
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update({k: v for k, v in record.__dict__.items() if k not in self._STANDARD_ATTRS})
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ModeFilter(logging.Filter):
    """
    Logging filter that drops records flagged for the other output mode.

    Records carry `json_only=True` (complete detail that text output truncates) or
    `text_only=True` (human-readable framing, e.g. "... and N more"). The text handler
    drops json_only records and the JSON handler drops text_only records.
    """

    def __init__(self, drop_attr):
        super().__init__()
        self._drop_attr = drop_attr

    def filter(self, record):
        return not getattr(record, self._drop_attr, False)


def _configure_logging():
    """
    Configures root logging: plain text by default, JSON lines when BRIDGE_LOG_FORMAT=json.

    Like logging.basicConfig, this does nothing if the host application has already
    configured logging, so an application's own setup always takes precedence. Applications
    using their own handlers should attach the matching ModeFilter as well as, for JSON,
    JsonFormatter: ModeFilter("text_only") on a JSON handler, ModeFilter("json_only") on a
    text handler. Without the filter, a JSON handler also receives text-only lines such as
    "... and N more", and a text handler receives every medium-risk OAuth token instead of
    the first 10.
    """
    handler = logging.StreamHandler()
    if os.environ.get("BRIDGE_LOG_FORMAT", "text").strip().lower() == "json":
        handler.setFormatter(JsonFormatter())
        handler.addFilter(ModeFilter("text_only"))
    else:
        handler.addFilter(ModeFilter("json_only"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])


_configure_logging()
logger = logging.getLogger(__name__)


def _get_graph_headers(tenant_id, client_id, client_secret):
    """
    Acquires a Microsoft Graph access token and returns authorization headers.

    Raises:
        RuntimeError: If authentication fails.
    """
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(f"Authentication failed: {result.get('error_description')}")
    return {
        "Authorization": f"Bearer {result['access_token']}",
        "Content-Type": "application/json"
    }


_RETRYABLE_STATUS = (429, 503)
_REQUEST_TIMEOUT = 30
_MAX_ATTEMPTS = 5
_MAX_BACKOFF = 60


def _graph_get(url, headers, params=None):
    """
    GET against Microsoft Graph with a timeout and retry on throttling.

    Retries on 429 and 503, honoring the Retry-After header and otherwise backing off
    exponentially (capped at _MAX_BACKOFF seconds). Returns the final response, which
    the caller checks with raise_for_status(). Network errors propagate as
    requests.exceptions.RequestException once attempts are exhausted.
    """
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=_REQUEST_TIMEOUT)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt == _MAX_ATTEMPTS:
                raise
            delay = min(2 ** attempt, _MAX_BACKOFF)
            logger.warning(f"Graph request failed ({e}); retrying in {delay}s (attempt {attempt}/{_MAX_ATTEMPTS})")
            time.sleep(delay)
            continue

        if response.status_code not in _RETRYABLE_STATUS or attempt == _MAX_ATTEMPTS:
            return response

        try:
            delay = min(float(response.headers.get("Retry-After")), _MAX_BACKOFF)
        except (TypeError, ValueError):
            delay = min(2 ** attempt, _MAX_BACKOFF)
        logger.warning(
            f"Graph returned {response.status_code}; retrying in {delay}s (attempt {attempt}/{_MAX_ATTEMPTS})"
        )
        time.sleep(delay)


def _parse_graph_datetime(value):
    """Parses a Graph ISO 8601 timestamp; returns None for missing or malformed values."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _last_activity(guest):
    """
    Returns the most recent sign-in time from a user's signInActivity, or None.

    Prefers lastSuccessfulSignInDateTime, since lastSignInDateTime and
    lastNonInteractiveSignInDateTime also record failed attempts, which would make a
    stale account under attack look active. That field is not backfilled before
    December 2023, so when it is absent this falls back to the later of the interactive
    and non-interactive times, so guests who only reach the tenant through token refresh
    or app access aren't mistaken for stale.
    """
    activity = guest.get("signInActivity") or {}
    successful = _parse_graph_datetime(activity.get("lastSuccessfulSignInDateTime"))
    if successful:
        return successful

    times = [
        _parse_graph_datetime(activity.get("lastSignInDateTime")),
        _parse_graph_datetime(activity.get("lastNonInteractiveSignInDateTime")),
    ]
    times = [t for t in times if t]
    return max(times) if times else None


def _guest_log_fields(guest):
    """Structured fields for a guest finding (see JsonFormatter)."""
    return {
        "user": guest["email"],
        "display_name": guest["display_name"],
        "domain": guest["domain"],
        "last_sign_in": guest["last_sign_in"],
        "created_at": guest["created"],
    }


def _guest_home_domain(guest):
    """
    Returns a B2B guest's home domain (the organization they belong to).

    Guest UPNs take the form 'jane_partner.com#EXT#@hosttenant.onmicrosoft.com', so the
    text after '@' is the host tenant, not the guest's organization. Prefer the mail
    attribute; otherwise recover the domain from the part before '#EXT#'.
    """
    mail = guest.get("mail")
    if mail and "@" in mail:
        return mail.rsplit("@", 1)[1].lower()

    upn = guest.get("userPrincipalName") or ""
    if "#EXT#" in upn:
        original = upn.split("#EXT#", 1)[0]
        # The original address's '@' became the last underscore.
        if "_" in original:
            return original.rsplit("_", 1)[1].lower()
    elif "@" in upn:
        return upn.rsplit("@", 1)[1].lower()

    return "Unknown"


def get_risk_detections(tenant_id, client_id, client_secret, hours_back=24, min_risk_level='medium'):
    """
    Queries Entra ID Identity Protection risk detections (identityProtection/riskDetections).

    Returns detections made within the specified time window, newest first. Filters by
    minimum risk level and logs detailed information for security investigation. A single
    sign-in can produce several detections, and offline detections (e.g. leaked credentials)
    may have no sign-in, IP address, or location attached.

    Args:
        tenant_id: Entra ID tenant ID
        client_id: App registration client ID
        client_secret: App registration client secret
        hours_back: Time window in hours (default: 24)
        min_risk_level: Minimum risk level to include ('low', 'medium', 'high', default: 'medium')

    Returns:
        List of riskDetection dictionaries. Each includes userPrincipalName, riskLevel,
        riskState, detectedDateTime, ipAddress, location (city, countryOrRegion), and
        riskEventType (a single string).

    Note: Requires IdentityRiskEvent.Read.All application permission with admin consent and
    an Entra ID P1/P2 license. The time window applies to detectedDateTime, when the risk was
    detected, which for offline detections can be later than the activity itself.
    """
    try:
        headers = _get_graph_headers(tenant_id, client_id, client_secret)
    except RuntimeError as e:
        logger.error(str(e))
        return []

    start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    risk_level_map = {"low": 0, "medium": 1, "high": 2}
    min_level = risk_level_map.get(min_risk_level.lower(), 1)

    graph_url = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
    # riskDetections documents $filter and $select only, so ordering is done in Python.
    params = {
        "$filter": f"detectedDateTime ge {start_time_str}",
    }

    try:
        detections = []
        page_url = graph_url

        while page_url:
            response = _graph_get(
                page_url,
                headers,
                params=params if page_url == graph_url else None
            )
            response.raise_for_status()
            data = response.json()
            detections.extend(data.get("value", []))
            page_url = data.get("@odata.nextLink")

        # Filter by risk level in Python. Levels outside low/medium/high ('none', 'hidden')
        # rank below 'low' and are never reported.
        filtered_detections = [
            s for s in detections
            if risk_level_map.get((s.get("riskLevel") or "").lower(), -1) >= min_level
        ]
        filtered_detections.sort(
            key=lambda s: _parse_graph_datetime(s.get("detectedDateTime")) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        if not filtered_detections:
            logger.info(
                f"No risk detections found in the last {hours_back} hours (minimum risk: {min_risk_level})",
                extra={
                    "event": "risk_detection_summary",
                    "findings": 0,
                    "hours_back": hours_back,
                    "min_risk_level": min_risk_level,
                },
            )
            return []

        logger.warning(
            f"Found {len(filtered_detections)} risk detection(s) in the last {hours_back} hours:",
            extra={
                "event": "risk_detection_summary",
                "findings": len(filtered_detections),
                "hours_back": hours_back,
                "min_risk_level": min_risk_level,
            },
        )

        for detection in filtered_detections:
            user_principal_name = detection.get("userPrincipalName", "Unknown")
            risk_level = detection.get("riskLevel") or "Unknown"
            risk_state = detection.get("riskState") or "Unknown"
            created_time = detection.get("detectedDateTime", "Unknown")
            ip_address = detection.get("ipAddress") or "Unknown"
            location = detection.get("location") or {}
            city = location.get("city") or "Unknown"
            country = location.get("countryOrRegion") or "Unknown"
            risk_event_type = detection.get("riskEventType")
            risk_event_types = [risk_event_type] if risk_event_type else []

            logger.warning(
                f"User: {user_principal_name} | Risk Level: {risk_level.upper()} | "
                f"Risk State: {risk_state} | Time: {created_time} | "
                f"IP: {ip_address} | Location: {city}, {country} | "
                f"Risk Events: {', '.join(risk_event_types) if risk_event_types else 'None'}",
                extra={
                    "event": "risk_detection",
                    "user": user_principal_name,
                    "risk_level": risk_level,
                    "risk_state": risk_state,
                    "time": created_time,
                    "ip_address": ip_address,
                    "city": city,
                    "country": country,
                    "risk_events": risk_event_types,
                },
            )

        return filtered_detections

    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying risk detections: {e}")
        if e.response is not None:
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

    Activity is read from signInActivity (the last successful sign-in when available,
    otherwise the later of the interactive and non-interactive attempts). Guests with no sign-in on record count as inactive only once their
    createdDateTime falls outside the inactivity window.

    Note: Requires User.Read.All (or Directory.Read.All) plus AuditLog.Read.All application
    permissions with admin consent. signInActivity requires an Entra ID P1/P2 license.
    """
    empty_result = {
        "trusted_active": [],
        "trusted_inactive": [],
        "untrusted_active": [],
        "untrusted_inactive": []
    }

    try:
        headers = _get_graph_headers(tenant_id, client_id, client_secret)
    except RuntimeError as e:
        logger.error(str(e))
        return empty_result

    if trusted_domains is None:
        trusted_domains = []

    graph_url = "https://graph.microsoft.com/v1.0/users"
    params = {
        "$filter": "userType eq 'Guest'",
        "$select": "id,userPrincipalName,displayName,mail,userType,externalUserState,createdDateTime,signInActivity"
    }

    try:
        guest_users = []
        page_url = graph_url

        while page_url:
            response = _graph_get(
                page_url,
                headers,
                params=params if page_url == graph_url else None
            )
            response.raise_for_status()
            data = response.json()
            guest_users.extend(data.get("value", []))
            page_url = data.get("@odata.nextLink")

        if not guest_users:
            logger.info("No guest users found in the directory.")
            return empty_result

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_inactive)

        trusted_active = []
        trusted_inactive = []
        untrusted_active = []
        untrusted_inactive = []

        if not any("signInActivity" in g for g in guest_users):
            logger.warning(
                "signInActivity was not returned for any guest. Check that the app has "
                "AuditLog.Read.All and the tenant has Entra ID P1/P2; until then, activity "
                "is judged from createdDateTime only."
            )

        for guest in guest_users:
            email = guest.get("mail") or guest.get("userPrincipalName") or "Unknown"
            domain = _guest_home_domain(guest)
            last_sign_in_dt = _last_activity(guest)
            last_sign_in = last_sign_in_dt.isoformat() if last_sign_in_dt else None
            display_name = guest.get("displayName", "Unknown")
            created = guest.get("createdDateTime", "Unknown")

            is_trusted = any(
                domain.lower() == trusted_domain.lower()
                or domain.lower().endswith("." + trusted_domain.lower())
                for trusted_domain in trusted_domains
            ) if trusted_domains else False

            if last_sign_in_dt:
                is_inactive = last_sign_in_dt < cutoff_date
            else:
                # No sign-in on record. A guest invited inside the window hasn't had a
                # chance to go stale yet; anything older that never signed in has.
                created_dt = _parse_graph_datetime(created)
                is_inactive = created_dt is None or created_dt < cutoff_date

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

        logger.info(
            f"Guest User Audit Report - Total guest users: {len(guest_users)}, "
            f"Inactive threshold: {days_inactive} days",
            extra={
                "event": "guest_audit_summary",
                "guests_total": len(guest_users),
                "days_inactive": days_inactive,
                "trusted_active": len(trusted_active),
                "trusted_inactive": len(trusted_inactive),
                "untrusted_active": len(untrusted_active),
                "untrusted_inactive": len(untrusted_inactive),
            },
        )

        if untrusted_inactive:
            logger.warning(f"UNTRUSTED INACTIVE ({len(untrusted_inactive)}):")
            for guest in untrusted_inactive:
                logger.warning(
                    f"  {guest['email']} ({guest['display_name']}) | "
                    f"Domain: {guest['domain']} | Last sign-in: {guest['last_sign_in']} | "
                    f"Created: {guest['created']}",
                    extra={"event": "guest_untrusted_inactive", **_guest_log_fields(guest)},
                )

        if untrusted_active:
            logger.warning(f"UNTRUSTED ACTIVE ({len(untrusted_active)}):")
            for guest in untrusted_active:
                logger.warning(
                    f"  {guest['email']} ({guest['display_name']}) | "
                    f"Domain: {guest['domain']} | Last sign-in: {guest['last_sign_in']}",
                    extra={"event": "guest_untrusted_active", **_guest_log_fields(guest)},
                )

        if trusted_inactive:
            logger.info(f"Trusted but Inactive ({len(trusted_inactive)}):")
            for guest in trusted_inactive:
                logger.info(
                    f"  {guest['email']} ({guest['display_name']}) | Last sign-in: {guest['last_sign_in']}",
                    extra={"event": "guest_trusted_inactive", **_guest_log_fields(guest)},
                )

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
        if e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return empty_result


def get_entra_users_with_changes(tenant_id, client_id, client_secret, filter_criteria=None):
    """
    Queries Entra ID for users matching filter criteria.

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
    try:
        headers = _get_graph_headers(tenant_id, client_id, client_secret)
    except RuntimeError as e:
        logger.error(str(e))
        return []

    if filter_criteria is None:
        filter_criteria = "officeLocation eq 'Seattle'"

    select_fields = "id,userPrincipalName,displayName,mail,officeLocation,department,jobTitle,employeeId"
    query_url = f"https://graph.microsoft.com/v1.0/users?$filter={filter_criteria}&$select={select_fields}"

    try:
        all_users = []
        page_url = query_url

        while page_url:
            response = _graph_get(page_url, headers)
            response.raise_for_status()
            data = response.json()
            page_users = data.get('value', [])
            all_users.extend(page_users)
            logger.debug(f"Retrieved {len(page_users)} users from current page")
            page_url = data.get('@odata.nextLink')

        logger.info(f"Found {len(all_users)} users matching criteria: {filter_criteria}")

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
        if e.response is not None:
            logger.error(f"Response: {e.response.text}")
        return []
