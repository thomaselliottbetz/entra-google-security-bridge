import json
import logging
import os
import subprocess
import sys

from unittest import mock

import identity_governance_ms as m

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _record(**extra):
    rec = logging.LogRecord("t", logging.WARNING, __file__, 1, "msg %s", ("x",), None)
    rec.__dict__.update(extra)
    return rec


def test_json_formatter_emits_stable_fields_and_extras():
    out = json.loads(m.JsonFormatter().format(_record(event="risky_sign_in", user="a@b.com", risk_events=["x"])))
    assert out["level"] == "WARNING" and out["message"] == "msg x" and out["logger"] == "t"
    assert out["event"] == "risky_sign_in" and out["user"] == "a@b.com" and out["risk_events"] == ["x"]
    assert out["timestamp"].endswith("+00:00")
    assert "args" not in out and "msg" not in out and "lineno" not in out


def test_json_formatter_serializes_unknown_types():
    json.loads(m.JsonFormatter().format(_record(when=object())))


def _run(fmt):
    code = ("import logging, identity_governance_ms as m;"
            "logging.getLogger('x').warning('hello', extra={'event': 'e'})")
    env = {**os.environ, "PYTHONPATH": ROOT}
    env.pop("BRIDGE_LOG_FORMAT", None)
    if fmt:
        env["BRIDGE_LOG_FORMAT"] = fmt
    return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=ROOT).stderr.strip()


def test_env_var_selects_json_and_text_is_default():
    assert json.loads(_run("json"))["event"] == "e"
    assert _run(None) == "WARNING:x:hello"


def test_finding_logs_carry_events(caplog):
    from unittest import mock
    sign_in = {"userPrincipalName": "u@x.com", "riskLevel": "high", "riskState": "atRisk",
               "detectedDateTime": "2026-01-01T00:00:00Z", "ipAddress": "1.2.3.4",
               "location": {"city": "Seattle", "countryOrRegion": "US"}, "riskEventType": "leakedCredentials"}
    resp = mock.Mock(status_code=200); resp.json.return_value = {"value": [sign_in]}
    with mock.patch.object(m, "_get_graph_headers", return_value={}), \
         mock.patch.object(m.requests, "get", return_value=resp), caplog.at_level("WARNING"):
        m.get_risky_sign_ins("t", "c", "s")
    rec = next(r for r in caplog.records if getattr(r, "event", "") == "risky_sign_in")
    assert rec.user == "u@x.com" and rec.risk_level == "high" and rec.country == "US"
    assert rec.time == "2026-01-01T00:00:00Z" and rec.risk_events == ["leakedCredentials"]


def _capture(fmt, fn):
    """Runs fn() under a handler configured like _configure_logging for the given mode."""
    import io
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    if fmt == "json":
        h.setFormatter(m.JsonFormatter())
        h.addFilter(m.ModeFilter("text_only"))
    else:
        h.addFilter(m.ModeFilter("json_only"))
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(h); root.setLevel(logging.INFO)
    try:
        fn()
    finally:
        root.removeHandler(h); root.setLevel(old_level)
    return [l for l in buf.getvalue().splitlines() if l]


def _medium_audit(n):
    import collaboration_security_google as g
    toks = [{"clientId": f"c{i}", "displayText": f"app{i}", "scopes": ["https://x/readonly"]} for i in range(n)]
    svc = mock.MagicMock()
    svc.users().list().execute.return_value = {"users": [{"primaryEmail": "u@x.com"}]}
    svc.tokens().list().execute.return_value = {"items": toks}
    with mock.patch.object(g.service_account.Credentials, "from_service_account_file"), \
         mock.patch.object(g, "_get_admin_email", return_value="a@x.com"), \
         mock.patch.object(g, "build", return_value=svc):
        return g.audit_oauth_tokens("creds.json")


def test_medium_risk_tokens_all_reach_json_but_text_is_truncated():
    jl = [json.loads(l) for l in _capture("json", lambda: _medium_audit(13))]
    assert sum(1 for r in jl if r.get("event") == "oauth_medium_risk_token") == 13
    assert not any("more" in r["message"] and "..." in r["message"] for r in jl)
    assert all("json_only" not in r and "text_only" not in r for r in jl)
    summary = next(r for r in jl if r.get("event") == "oauth_audit_summary")
    assert summary["medium_risk"] == 13 and summary["users_audited"] == 1

    text = _capture("text", lambda: _medium_audit(13))
    assert sum(1 for l in text if "User: u@x.com | App: app" in l) == 10
    assert any("... and 3 more" in l for l in text)


def test_guest_audit_emits_trusted_inactive_and_summary():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    iso = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
    guests = [{"userPrincipalName": "a_partner.com#EXT#@h.onmicrosoft.com", "mail": "a@partner.com",
               "createdDateTime": iso(400), "signInActivity": {"lastSuccessfulSignInDateTime": iso(200)}}]
    resp = mock.Mock(); resp.json.return_value = {"value": guests}; resp.raise_for_status.return_value = None

    def run():
        with mock.patch.object(m, "_get_graph_headers", return_value={}), \
             mock.patch.object(m.requests, "get", return_value=resp):
            m.audit_guest_users("t", "c", "s", trusted_domains=["partner.com"], days_inactive=90)

    jl = [json.loads(l) for l in _capture("json", run)]
    ti = next(r for r in jl if r.get("event") == "guest_trusted_inactive")
    assert ti["user"] == "a@partner.com" and ti["domain"] == "partner.com"
    s = next(r for r in jl if r.get("event") == "guest_audit_summary")
    assert (s["guests_total"], s["trusted_inactive"], s["untrusted_inactive"]) == (1, 1, 0)


def test_risky_sign_in_summary_emitted_even_with_zero_findings():
    resp = mock.Mock(status_code=200); resp.json.return_value = {"value": []}

    def run():
        with mock.patch.object(m, "_get_graph_headers", return_value={}), \
             mock.patch.object(m.requests, "get", return_value=resp):
            m.get_risky_sign_ins("t", "c", "s")

    s = next(json.loads(l) for l in _capture("json", run) if '"risky_sign_in_summary"' in l)
    assert s["findings"] == 0 and s["hours_back"] == 24
