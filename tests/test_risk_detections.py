import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import identity_governance_ms as m


def _det(level, when, **kw):
    return {"userPrincipalName": f"{level}@x.com", "riskLevel": level, "riskState": "atRisk",
            "detectedDateTime": when, "riskEventType": "unfamiliarFeatures", **kw}


def _run(detections, **kw):
    resp = mock.Mock(status_code=200); resp.json.return_value = {"value": detections}
    with mock.patch.object(m, "_get_graph_headers", return_value={}), \
         mock.patch.object(m.requests, "get", return_value=resp) as get:
        return m.get_risky_sign_ins("t", "c", "s", **kw), get


def test_queries_risk_detections_filtered_on_detected_time():
    _, get = _run([])
    assert get.call_args.args[0] == "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
    params = get.call_args.kwargs["params"]
    assert params["$filter"].startswith("detectedDateTime ge ")
    assert "$orderby" not in params


def test_results_sorted_newest_first_and_levels_filtered():
    out, _ = _run([
        _det("medium", "2026-01-01T00:00:00Z"),
        _det("high", "2026-01-03T00:00:00.5Z"),
        _det("low", "2026-01-04T00:00:00Z"),
        _det("none", "2026-01-05T00:00:00Z"),
        _det("high", "2026-01-02T00:00:00Z"),
    ])
    assert [d["detectedDateTime"] for d in out] == [
        "2026-01-03T00:00:00.5Z", "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"]


def test_min_low_includes_low_but_not_none_or_hidden():
    out, _ = _run([_det("low", "2026-01-01T00:00:00Z"), _det("none", "2026-01-02T00:00:00Z"),
                   _det("hidden", "2026-01-03T00:00:00Z")], min_risk_level="low")
    assert [d["riskLevel"] for d in out] == ["low"]


def test_offline_detection_without_location_or_ip_does_not_crash(caplog):
    det = _det("high", "2026-01-01T00:00:00Z", riskEventType="leakedCredentials",
               ipAddress=None, location=None)
    with caplog.at_level("WARNING"):
        out, _ = _run([det])
    assert len(out) == 1
    rec = next(r for r in caplog.records if getattr(r, "event", "") == "risky_sign_in")
    assert rec.ip_address == "Unknown" and rec.city == "Unknown" and rec.risk_events == ["leakedCredentials"]


def test_missing_event_type_yields_empty_list(caplog):
    det = _det("high", "2026-01-01T00:00:00Z"); det.pop("riskEventType")
    with caplog.at_level("WARNING"):
        _run([det])
    rec = next(r for r in caplog.records if getattr(r, "event", "") == "risky_sign_in")
    assert rec.risk_events == []
