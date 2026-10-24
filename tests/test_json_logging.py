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
               "createdDateTime": "2026-01-01T00:00:00Z", "ipAddress": "1.2.3.4",
               "location": {"city": "Seattle", "countryOrRegion": "US"}, "riskEventTypes": ["leakedCredentials"]}
    resp = mock.Mock(status_code=200); resp.json.return_value = {"value": [sign_in]}
    with mock.patch.object(m, "_get_graph_headers", return_value={}), \
         mock.patch.object(m.requests, "get", return_value=resp), caplog.at_level("WARNING"):
        m.get_risky_sign_ins("t", "c", "s")
    rec = next(r for r in caplog.records if getattr(r, "event", "") == "risky_sign_in")
    assert rec.user == "u@x.com" and rec.risk_level == "high" and rec.country == "US"
