import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest import mock

import identity_governance_ms as m


def _resp(payload):
    r = mock.Mock()
    r.status_code = 200
    r.json.return_value = payload
    r.raise_for_status.return_value = None
    return r


def test_filter_is_sent_as_param_not_interpolated():
    tricky = "displayName eq 'A&B #1' and department eq 'R&D'"
    next_link = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    pages = [_resp({"value": [{"id": "1"}], "@odata.nextLink": next_link}),
             _resp({"value": [{"id": "2"}]})]
    with mock.patch.object(m, "_get_graph_headers", return_value={}), \
         mock.patch.object(m.requests, "get", side_effect=pages) as get:
        users = m.get_entra_users_with_changes("t", "c", "s", filter_criteria=tricky)

    assert [u["id"] for u in users] == ["1", "2"]
    first, second = get.call_args_list
    assert first.args[0] == "https://graph.microsoft.com/v1.0/users"
    assert first.kwargs["params"]["$filter"] == tricky
    assert "$select" in first.kwargs["params"]
    assert second.args[0] == next_link
    assert second.kwargs["params"] is None
