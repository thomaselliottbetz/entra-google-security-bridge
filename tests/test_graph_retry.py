import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import identity_governance_ms as m


def _resp(status, retry_after=None):
    r = mock.Mock(status_code=status)
    r.headers = {"Retry-After": retry_after} if retry_after else {}
    return r


def test_retries_429_honoring_retry_after_then_succeeds():
    seq = [_resp(429, "7"), _resp(503), _resp(200)]
    with mock.patch.object(m.requests, "get", side_effect=seq) as get, \
         mock.patch.object(m.time, "sleep") as sleep:
        out = m._graph_get("https://graph", {})
    assert out.status_code == 200 and get.call_count == 3
    assert [c.args[0] for c in sleep.call_args_list] == [7.0, 4]
    assert all(c.kwargs["timeout"] == m._REQUEST_TIMEOUT for c in get.call_args_list)


def test_gives_up_after_max_attempts_and_returns_last_response():
    with mock.patch.object(m.requests, "get", return_value=_resp(429)) as get, \
         mock.patch.object(m.time, "sleep"):
        out = m._graph_get("https://graph", {})
    assert out.status_code == 429 and get.call_count == m._MAX_ATTEMPTS


def test_non_retryable_status_returns_immediately():
    with mock.patch.object(m.requests, "get", return_value=_resp(404)) as get, \
         mock.patch.object(m.time, "sleep") as sleep:
        m._graph_get("https://graph", {})
    assert get.call_count == 1 and not sleep.called
