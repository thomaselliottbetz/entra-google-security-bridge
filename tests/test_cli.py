import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import logging
from unittest import mock

import pytest

import bridge_cli as cli
import collaboration_security_google as g
import identity_governance_ms as m

ENTRA_ENV = {"ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c", "ENTRA_CLIENT_SECRET": "s"}
GOOGLE_ENV = {"GOOGLE_CREDENTIALS_PATH": "creds.json", "GOOGLE_ADMIN_EMAIL": "admin@example.com"}


@pytest.fixture(autouse=True)
def _no_logging_setup(monkeypatch):
    """main() configures logging; keep tests from touching the root logger."""
    monkeypatch.setattr(m, "configure_logging", lambda: None)


@pytest.fixture
def env(monkeypatch):
    for k in (*ENTRA_ENV, *GOOGLE_ENV):
        monkeypatch.delenv(k, raising=False)

    def setenv(*dicts):
        for d in dicts:
            for k, v in d.items():
                monkeypatch.setenv(k, v)
    return setenv


def test_risk_detections_passes_arguments_and_exits_zero(env):
    env(ENTRA_ENV)
    with mock.patch.object(m, "get_risk_detections", return_value=[{"id": 1}]) as f:
        code = cli.main(["risk-detections", "--hours-back", "6", "--min-risk-level", "high"])
    assert code == cli.EXIT_OK
    f.assert_called_once_with("t", "c", "s", hours_back=6, min_risk_level="high")


def test_fail_on_findings_exits_one_only_when_requested(env):
    env(ENTRA_ENV)
    with mock.patch.object(m, "get_risk_detections", return_value=[{"id": 1}]):
        assert cli.main(["risk-detections"]) == cli.EXIT_OK
        assert cli.main(["risk-detections", "--fail-on-findings"]) == cli.EXIT_FINDINGS
    with mock.patch.object(m, "get_risk_detections", return_value=[]):
        assert cli.main(["risk-detections", "--fail-on-findings"]) == cli.EXIT_OK


def test_logged_error_makes_the_run_fail_even_with_empty_results(env):
    env(ENTRA_ENV)

    def failing(*a, **kw):
        logging.getLogger("identity_governance_ms").error("Authentication failed")
        return []

    with mock.patch.object(m, "get_risk_detections", side_effect=failing):
        assert cli.main(["risk-detections"]) == cli.EXIT_FAILED


def test_unexpected_exception_exits_failed(env):
    env(ENTRA_ENV)
    with mock.patch.object(m, "get_risk_detections", side_effect=RuntimeError("boom")):
        assert cli.main(["risk-detections"]) == cli.EXIT_FAILED


def test_missing_secret_is_a_usage_error_and_never_calls_the_api(env):
    env({"ENTRA_TENANT_ID": "t", "ENTRA_CLIENT_ID": "c"})
    with mock.patch.object(m, "get_risk_detections") as f, pytest.raises(SystemExit) as exc:
        cli.main(["risk-detections"])
    assert exc.value.code == cli.EXIT_USAGE
    f.assert_not_called()


def test_guest_audit_counts_untrusted_and_trusted_inactive_as_findings(env):
    env(ENTRA_ENV)
    report = {"trusted_active": [1], "trusted_inactive": [], "untrusted_active": [],
              "untrusted_inactive": []}
    with mock.patch.object(m, "audit_guest_users", return_value=report) as f:
        assert cli.main(["guest-audit", "--fail-on-findings", "--trusted-domain", "a.com",
                         "--trusted-domain", "b.com", "--days-inactive", "30"]) == cli.EXIT_OK
    f.assert_called_once_with("t", "c", "s", trusted_domains=["a.com", "b.com"], days_inactive=30)
    report["untrusted_inactive"] = [1]
    with mock.patch.object(m, "audit_guest_users", return_value=report):
        assert cli.main(["guest-audit", "--fail-on-findings"]) == cli.EXIT_FINDINGS


def test_oauth_audit_reads_approved_file_and_extends_default_scopes(env, tmp_path):
    env(GOOGLE_ENV)
    approved = tmp_path / "approved.txt"
    approved.write_text("# vetted\nclient-1\n\nclient-2\n")
    report = {"high_risk": [], "medium_risk": [], "low_risk": [], "errors": []}
    with mock.patch.object(g, "audit_oauth_tokens", return_value=report) as f:
        code = cli.main(["oauth-audit", "--approved-app", "client-0",
                         "--approved-apps-file", str(approved), "--extra-blocked-scope", "extra-scope"])
    assert code == cli.EXIT_OK
    args, kwargs = f.call_args
    assert args == ("creds.json",)
    assert kwargs["approved_apps"] == ["client-0", "client-1", "client-2"]
    assert kwargs["blocked_scopes"] == [*g.DEFAULT_BLOCKED_SCOPES, "extra-scope"]


def test_oauth_audit_defaults_and_coverage_gap_fails_the_run(env):
    env(GOOGLE_ENV)
    report = {"high_risk": [], "medium_risk": [], "low_risk": [],
              "errors": [{"user": "u@x.com", "error": "403"}]}
    with mock.patch.object(g, "audit_oauth_tokens", return_value=report) as f:
        assert cli.main(["oauth-audit"]) == cli.EXIT_FAILED
    assert f.call_args.kwargs == {"blocked_scopes": None, "approved_apps": None}


def test_oauth_audit_requires_google_settings(env):
    env({"GOOGLE_CREDENTIALS_PATH": "creds.json"})
    with pytest.raises(SystemExit) as exc:
        cli.main(["oauth-audit"])
    assert exc.value.code == cli.EXIT_USAGE


def _sync_args(tmp_path, *extra):
    mapping = tmp_path / "mapping.json"
    mapping.write_text(json.dumps({"officeLocation": {"Seattle": "/Eng/Seattle"}}))
    return ["ou-sync", "--ou-mapping-file", str(mapping), "--filter", "officeLocation eq 'Seattle'", *extra]


def test_ou_sync_is_a_dry_run_unless_apply_is_given(env, tmp_path):
    env(ENTRA_ENV, GOOGLE_ENV)
    result = {"synced": [], "skipped": [], "failed": [], "unmapped": [], "unchanged": [], "would_sync": []}
    with mock.patch.object(g, "sync_entra_to_google_ou", return_value=result) as f:
        assert cli.main(_sync_args(tmp_path, "--email-domain-map", "@a.com=@b.com")) == cli.EXIT_OK
        assert f.call_args.kwargs["dry_run"] is True
        assert cli.main(_sync_args(tmp_path, "--apply")) == cli.EXIT_OK
        assert f.call_args.kwargs["dry_run"] is False
    first = f.call_args_list[0]
    assert first.args == ("t", "c", "s", "creds.json")
    assert first.kwargs["ou_mapping"] == {"officeLocation": {"Seattle": "/Eng/Seattle"}}
    assert first.kwargs["email_domain_mapping"] == {"@a.com": "@b.com"}


def test_ou_sync_failed_updates_fail_the_run(env, tmp_path):
    env(ENTRA_ENV, GOOGLE_ENV)
    result = {"synced": [], "skipped": [], "failed": [{"email": "a", "target_ou": "/x", "error": "e"}],
              "unmapped": [], "unchanged": [], "would_sync": []}
    with mock.patch.object(g, "sync_entra_to_google_ou", return_value=result):
        assert cli.main(_sync_args(tmp_path, "--apply")) == cli.EXIT_FAILED


def test_ou_sync_rejects_bad_mapping_file_and_domain_map(env, tmp_path):
    env(ENTRA_ENV, GOOGLE_ENV)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(SystemExit) as exc:
        cli.main(["ou-sync", "--ou-mapping-file", str(bad), "--filter", "x eq 'y'"])
    assert exc.value.code == cli.EXIT_USAGE
    with pytest.raises(SystemExit) as exc:
        cli.main(_sync_args(tmp_path, "--email-domain-map", "no-equals-sign"))
    assert exc.value.code == cli.EXIT_USAGE


def test_error_counter_is_detached_after_each_run(env):
    env(ENTRA_ENV)
    before = list(logging.getLogger().handlers)
    with mock.patch.object(m, "get_risk_detections", return_value=[]):
        cli.main(["risk-detections"])
    assert logging.getLogger().handlers == before


def test_main_configures_logging_before_running(env, monkeypatch):
    env(ENTRA_ENV)
    calls = []
    monkeypatch.setattr(m, "configure_logging", lambda: calls.append("configure"))
    with mock.patch.object(m, "get_risk_detections", side_effect=lambda *a, **k: calls.append("run") or []):
        cli.main(["risk-detections"])
    assert calls == ["configure", "run"]
