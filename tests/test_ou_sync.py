import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import pytest
from googleapiclient.errors import HttpError

import collaboration_security_google as g


def _http_error(status):
    return HttpError(mock.Mock(status=status, reason="x"), b"{}")


def _sync(lookup_results):
    """lookup_results: {email: dict | Exception} returned by users().get().execute()."""
    entra = [{"userPrincipalName": e, "officeLocation": "Seattle"} for e in lookup_results]
    svc = mock.MagicMock()

    def get(userKey):
        req = mock.Mock()
        r = lookup_results[userKey]
        if isinstance(r, Exception):
            req.execute.side_effect = r
        else:
            req.execute.return_value = r
        return req

    svc.users().get.side_effect = get
    with mock.patch.object(g, "get_entra_users_with_changes", return_value=entra), \
         mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="admin@example.com"), \
         mock.patch.object(g, "build", return_value=svc):
        return g.sync_entra_to_google_ou("t", "c", "s", "creds.json")


def test_only_404_is_skipped_other_lookup_errors_fail():
    result = _sync({
        "gone@example.com": _http_error(404),
        "denied@example.com": _http_error(403),
        "throttled@example.com": _http_error(429),
        "down@example.com": _http_error(503),
        "net@example.com": OSError("connection reset"),
        "ok@example.com": {"orgUnitPath": "/Engineering/Seattle"},
    })
    assert result["skipped"] == ["gone@example.com"]
    assert sorted(f["email"] for f in result["failed"]) == [
        "denied@example.com", "down@example.com", "net@example.com", "throttled@example.com"]
    assert all(f["target_ou"] is None for f in result["failed"])
    assert result["synced"] == []


def test_every_user_lands_in_exactly_one_bucket():
    entra = [
        {"userPrincipalName": "move@example.com", "officeLocation": "Seattle"},
        {"userPrincipalName": "same@example.com", "officeLocation": "Seattle"},
        {"userPrincipalName": "nomap@example.com", "officeLocation": "Paris"},
        {"userPrincipalName": "gone@example.com", "officeLocation": "Seattle"},
    ]
    ous = {
        "move@example.com": "/Sales",
        "same@example.com": "/Engineering/Seattle",
        "nomap@example.com": "/Sales",
        "gone@example.com": _http_error(404),
    }
    svc = mock.MagicMock()

    def get(userKey):
        req = mock.Mock()
        r = ous[userKey]
        if isinstance(r, Exception):
            req.execute.side_effect = r
        else:
            req.execute.return_value = {"orgUnitPath": r}
        return req

    svc.users().get.side_effect = get
    with mock.patch.object(g, "get_entra_users_with_changes", return_value=entra), \
         mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="admin@example.com"), \
         mock.patch.object(g, "build", return_value=svc):
        r = g.sync_entra_to_google_ou("t", "c", "s", "creds.json")

    assert [x["email"] for x in r["synced"]] == ["move@example.com"]
    assert r["unchanged"] == ["same@example.com"]
    assert r["unmapped"] == ["nomap@example.com"]
    assert r["skipped"] == ["gone@example.com"]
    assert r["failed"] == []
    assert sum(len(r[k]) for k in r) == len(entra)


def _sync_run(entra, current_ous, update_errors=None, **kw):
    """Runs a sync against mocks; returns (result, service). current_ous maps google email -> OU."""
    update_errors = update_errors or {}
    svc = mock.MagicMock()

    def get(userKey):
        req = mock.Mock()
        req.execute.return_value = {"orgUnitPath": current_ous[userKey]}
        return req

    def update(userKey, body):
        req = mock.Mock()
        if userKey in update_errors:
            req.execute.side_effect = update_errors[userKey]
        return req

    svc.users().get.side_effect = get
    svc.users().update.side_effect = update
    with mock.patch.object(g, "get_entra_users_with_changes", return_value=entra), \
         mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="admin@example.com"), \
         mock.patch.object(g, "build", return_value=svc) as build:
        result = g.sync_entra_to_google_ou("t", "c", "s", "creds.json", **kw)
    return result, svc, build


def _seattle(email):
    return {"userPrincipalName": email, "officeLocation": "Seattle"}


def test_sync_moves_user_and_records_previous_ou():
    result, svc, _ = _sync_run([_seattle("a@example.com")], {"a@example.com": "/Sales"})
    assert result["synced"] == [{
        "email": "a@example.com", "source_attr": "officeLocation", "source_value": "Seattle",
        "target_ou": "/Engineering/Seattle", "previous_ou": "/Sales"}]
    svc.users().update.assert_called_once_with(
        userKey="a@example.com", body={"orgUnitPath": "/Engineering/Seattle"})


def test_sync_update_failure_goes_to_failed_and_run_continues():
    entra = [_seattle("bad@example.com"), _seattle("good@example.com")]
    ous = {"bad@example.com": "/Sales", "good@example.com": "/Sales"}
    result, _, _ = _sync_run(entra, ous, update_errors={"bad@example.com": RuntimeError("403")})
    assert [x["email"] for x in result["synced"]] == ["good@example.com"]
    assert result["failed"] == [{
        "email": "bad@example.com", "target_ou": "/Engineering/Seattle", "error": "403"}]


def test_sync_applies_email_domain_mapping_to_google_calls():
    result, svc, _ = _sync_run(
        [_seattle("a@company.com")], {"a@company.google.com": "/Sales"},
        email_domain_mapping={"@company.com": "@company.google.com"})
    assert [x["email"] for x in result["synced"]] == ["a@company.google.com"]
    svc.users().update.assert_called_once_with(
        userKey="a@company.google.com", body={"orgUnitPath": "/Engineering/Seattle"})


def test_sync_builds_one_service_client_for_all_users():
    entra = [_seattle(f"u{i}@example.com") for i in range(3)]
    _, _, build = _sync_run(entra, {f"u{i}@example.com": "/Sales" for i in range(3)})
    assert build.call_count == 1


def test_sync_first_matching_mapping_wins():
    user = {"userPrincipalName": "a@example.com", "officeLocation": "Seattle", "department": "Eng"}
    mapping = {"officeLocation": {"Seattle": "/Seattle"}, "department": {"Eng": "/Eng"}}
    result, _, _ = _sync_run([user], {"a@example.com": "/Sales"}, ou_mapping=mapping)
    assert result["synced"][0]["target_ou"] == "/Seattle"


def test_sync_with_no_entra_users_returns_all_keys_and_touches_nothing():
    with mock.patch.object(g, "get_entra_users_with_changes", return_value=[]), \
         mock.patch.object(g, "build") as build:
        result = g.sync_entra_to_google_ou("t", "c", "s", "creds.json")
    assert result == {"synced": [], "skipped": [], "failed": [], "unmapped": [], "unchanged": [], "would_sync": []}
    build.assert_not_called()


def test_sync_dry_run_reports_moves_without_updating():
    entra = [_seattle("a@example.com"), _seattle("same@example.com")]
    ous = {"a@example.com": "/Sales", "same@example.com": "/Engineering/Seattle"}
    result, svc, _ = _sync_run(entra, ous, dry_run=True)
    svc.users().update.assert_not_called()
    assert result["synced"] == []
    assert result["would_sync"] == [{
        "email": "a@example.com", "source_attr": "officeLocation", "source_value": "Seattle",
        "target_ou": "/Engineering/Seattle", "previous_ou": "/Sales"}]
    assert result["unchanged"] == ["same@example.com"]


def test_sync_dry_run_still_reports_lookup_failures():
    entra = [_seattle("denied@example.com"), _seattle("gone@example.com")]
    errors = {"denied@example.com": _http_error(403), "gone@example.com": _http_error(404)}
    svc = mock.MagicMock()

    def get(userKey):
        req = mock.Mock()
        req.execute.side_effect = errors[userKey]
        return req

    svc.users().get.side_effect = get
    with mock.patch.object(g, "get_entra_users_with_changes", return_value=entra), \
         mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="admin@example.com"), \
         mock.patch.object(g, "build", return_value=svc):
        result = g.sync_entra_to_google_ou("t", "c", "s", "creds.json", dry_run=True)
    assert result["skipped"] == ["gone@example.com"]
    assert [f["email"] for f in result["failed"]] == ["denied@example.com"]
    svc.users().update.assert_not_called()


def test_sync_dry_run_emits_events_and_flags_summary(caplog):
    with caplog.at_level("INFO"):
        _sync_run([_seattle("a@example.com")], {"a@example.com": "/Sales"}, dry_run=True)
    by_event = {getattr(r, "event", None): r for r in caplog.records}
    assert by_event["ou_sync_would_move"].target_ou == "/Engineering/Seattle"
    summary = by_event["ou_sync_summary"]
    assert (summary.dry_run, summary.would_sync, summary.synced) == (True, 1, 0)
