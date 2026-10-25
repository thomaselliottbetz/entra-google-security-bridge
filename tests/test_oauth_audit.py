import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import collaboration_security_google as g

DRIVE = "https://www.googleapis.com/auth/drive"


def _service(tokens_by_user):
    svc = mock.MagicMock()
    svc.users().list().execute.return_value = {
        "users": [{"primaryEmail": u} for u in tokens_by_user]
    }

    def tokens_list(userKey):
        req = mock.Mock()
        result = tokens_by_user[userKey]
        if isinstance(result, Exception):
            req.execute.side_effect = result
        else:
            req.execute.return_value = {"items": result}
        return req

    svc.tokens().list.side_effect = tokens_list
    return svc


def _audit(tokens_by_user, **kw):
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="a@x.com"), \
         mock.patch.object(g, "build", return_value=_service(tokens_by_user)):
        return g.audit_oauth_tokens("creds.json", **kw)


def test_allowlist_matches_client_id_not_display_name():
    tokens = {"u@x.com": [
        {"clientId": "good-123", "displayText": "Slack", "scopes": [DRIVE]},
        {"clientId": "evil-999", "displayText": "Microsoft Helper Pro", "scopes": [DRIVE]},
        {"clientId": "evil-998-good-123", "displayText": "x", "scopes": [DRIVE]},
    ]}
    r = _audit(tokens, approved_apps={"GOOD-123": "Slack"})
    assert [t["client_id"] for t in r["medium_risk"]] == ["good-123"]
    assert sorted(t["client_id"] for t in r["high_risk"]) == ["evil-998-good-123", "evil-999"]


def test_token_failures_are_reported(caplog):
    tokens = {"ok@x.com": [], "bad@x.com": RuntimeError("403 forbidden")}
    with caplog.at_level("WARNING"):
        r = _audit(tokens)
    assert r["errors"] == [{"user": "bad@x.com", "error": "403 forbidden"}]
    assert any("COVERAGE GAP" in m for m in caplog.messages)


def test_total_failure_returns_full_shape_and_no_summary(caplog):
    svc = mock.MagicMock()
    svc.users().list().execute.side_effect = RuntimeError("500 backend")
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="a@x.com"), \
         mock.patch.object(g, "build", return_value=svc), \
         caplog.at_level("INFO"):
        r = g.audit_oauth_tokens("creds.json")
    assert r == {"high_risk": [], "medium_risk": [], "low_risk": [],
                 "errors": [{"user": None, "error": "500 backend"}]}
    events = [getattr(rec, "event", None) for rec in caplog.records]
    assert "oauth_audit_failed" in events
    assert "oauth_audit_summary" not in events


def test_default_blocked_scopes_flag_full_gmail_and_cloud_platform():
    for scope in ("https://mail.google.com/",
                  "https://www.googleapis.com/auth/gmail.modify",
                  "https://www.googleapis.com/auth/cloud-platform"):
        r = _audit({"u@x.com": [{"clientId": "unknown-1", "displayText": "App", "scopes": [scope]}]})
        assert [t["client_id"] for t in r["high_risk"]] == ["unknown-1"], scope


def test_anonymous_flag_does_not_change_tier():
    tok = {"clientId": "c1", "displayText": "App", "scopes": ["https://www.googleapis.com/auth/calendar"]}
    plain = _audit({"u@x.com": [dict(tok, anonymous=False)]})
    anon = _audit({"u@x.com": [dict(tok, anonymous=True)]})
    assert len(plain["medium_risk"]) == len(anon["medium_risk"]) == 1
    assert anon["medium_risk"][0]["anonymous"] is True
