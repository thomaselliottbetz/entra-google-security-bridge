import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import pytest

import collaboration_security_google as g


def _move(current_ou):
    """Runs move_user_between_ous against a mocked directory; returns (service, exception)."""
    svc = mock.MagicMock()
    svc.users().get().execute.return_value = {"orgUnitPath": current_ou}
    error = None
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="admin@example.com"), \
         mock.patch.object(g, "build", return_value=svc):
        try:
            g.move_user_between_ous("u@example.com", "/Eng", "/Eng/A", "creds.json")
        except Exception as e:
            error = e
    return svc, error


def test_moves_when_source_matches():
    svc, error = _move("/Eng")
    assert error is None
    svc.users().update.assert_called_once_with(
        userKey="u@example.com", body={"orgUnitPath": "/Eng/A"})


def test_mismatch_raises_and_does_not_move():
    svc, error = _move("/Sales")
    assert isinstance(error, ValueError)
    assert "'/Sales'" in str(error) and "'/Eng'" in str(error)
    svc.users().update.assert_not_called()


def _run(fn, *args, update_error=None):
    svc = mock.MagicMock()
    svc.users().get().execute.return_value = {"orgUnitPath": "/Eng"}
    if update_error:
        svc.users().update().execute.side_effect = update_error
    svc.reset_mock(return_value=False, side_effect=False)
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file") as load, \
         mock.patch.object(g, "_get_admin_email", return_value="admin@example.com") as admin, \
         mock.patch.object(g, "build", return_value=svc):
        error = None
        try:
            fn(*args)
        except Exception as e:
            error = e
    return svc, load, admin, error


def test_move_user_to_ou_updates_without_reading_first():
    svc, load, _, error = _run(g.move_user_to_ou, "u@example.com", "/Eng/A", "creds.json")
    assert error is None
    svc.users().update.assert_called_once_with(
        userKey="u@example.com", body={"orgUnitPath": "/Eng/A"})
    svc.users().get.assert_not_called()


def test_move_user_to_ou_reraises_api_errors():
    boom = RuntimeError("403 forbidden")
    _, _, _, error = _run(g.move_user_to_ou, "u@example.com", "/Eng/A", "creds.json", update_error=boom)
    assert error is boom


def test_move_user_between_ous_reraises_update_errors():
    boom = RuntimeError("500 backend")
    _, _, _, error = _run(
        g.move_user_between_ous, "u@example.com", "/Eng", "/Eng/A", "creds.json", update_error=boom)
    assert error is boom


def test_move_functions_impersonate_the_configured_admin():
    for fn, args in ((g.move_user_to_ou, ("u@example.com", "/A", "creds.json")),
                     (g.move_user_between_ous, ("u@example.com", "/Eng", "/A", "creds.json"))):
        _, load, admin, _ = _run(fn, *args)
        admin.assert_called_once()
        load.return_value.with_subject.assert_called_once_with("admin@example.com")


def test_missing_admin_email_raises_before_any_api_call(monkeypatch):
    monkeypatch.delenv("GOOGLE_ADMIN_EMAIL", raising=False)
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "build") as build:
        with pytest.raises(ValueError):
            g.move_user_to_ou("u@example.com", "/A", "creds.json")
    build.assert_not_called()


def test_move_user_to_ou_dry_run_makes_no_update():
    svc, _, _, error = _run(g.move_user_to_ou, "u@example.com", "/Eng/A", "creds.json", True)
    assert error is None
    svc.users().update.assert_not_called()


def test_move_user_between_ous_dry_run_checks_source_but_does_not_update():
    svc, _, _, error = _run(g.move_user_between_ous, "u@example.com", "/Eng", "/Eng/A", "creds.json", True)
    assert error is None
    svc.users().get.assert_called()
    svc.users().update.assert_not_called()


def test_move_user_between_ous_dry_run_still_raises_on_mismatch():
    svc, _, _, error = _run(g.move_user_between_ous, "u@example.com", "/Sales", "/Eng/A", "creds.json", True)
    assert isinstance(error, ValueError)
    svc.users().update.assert_not_called()


def test_move_calls_retry_transient_errors():
    svc, _, _, _ = _run(g.move_user_to_ou, "u@example.com", "/Eng/A", "creds.json")
    svc.users().update().execute.assert_called_with(num_retries=g._API_RETRIES)
    svc, _, _, _ = _run(g.move_user_between_ous, "u@example.com", "/Eng", "/Eng/A", "creds.json")
    svc.users().get().execute.assert_called_with(num_retries=g._API_RETRIES)
    svc.users().update().execute.assert_called_with(num_retries=g._API_RETRIES)


def test_refused_preflight_is_not_logged_as_an_error(caplog):
    with caplog.at_level("INFO"):
        _, error = _move("/Sales")
    assert isinstance(error, g.OUMismatchError) and isinstance(error, ValueError)
    assert [r for r in caplog.records if r.levelname == "ERROR"] == []


def test_api_failure_during_preflight_is_logged_once(caplog):
    boom = RuntimeError("500 backend")
    with caplog.at_level("INFO"):
        _run(g.move_user_between_ous, "u@example.com", "/Eng", "/Eng/A", "creds.json", update_error=boom)
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1
