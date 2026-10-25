import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import collaboration_security_google as g

BASE = "https://www.googleapis.com/auth/admin.directory.user"


def _scopes_requested(call):
    """Runs call() with Google auth mocked; returns the scopes passed to the credentials loader."""
    svc = mock.MagicMock()
    svc.users().list().execute.return_value = {"users": []}
    svc.users().get().execute.return_value = {"orgUnitPath": "/Eng"}
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file") as load, \
         mock.patch.object(g, "_get_admin_email", return_value="a@x.com"), \
         mock.patch.object(g, "build", return_value=svc), \
         mock.patch.object(g, "get_entra_users_with_changes", return_value=[{"userPrincipalName": "u@x.com"}]):
        call()
    return set(load.call_args.kwargs["scopes"])


def test_audit_tier_has_read_and_security_only():
    scopes = _scopes_requested(lambda: g.audit_oauth_tokens("creds.json"))
    assert scopes == {BASE + ".readonly", BASE + ".security"}


def test_move_and_sync_tier_has_user_scope_only():
    assert _scopes_requested(lambda: g.move_user_to_ou("u@x.com", "/A", "creds.json")) == {BASE}
    assert _scopes_requested(
        lambda: g.move_user_between_ous("u@x.com", "/Eng", "/A", "creds.json")) == {BASE}
    assert _scopes_requested(lambda: g.sync_entra_to_google_ou("t", "c", "s", "creds.json")) == {BASE}
