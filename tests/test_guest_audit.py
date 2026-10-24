import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timedelta, timezone
from unittest import mock

import identity_governance_ms as m


def test_guest_audit_domains_and_activity():
    now = datetime.now(timezone.utc)
    iso = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
    guests = [
      # partner guest, mail populated, signed in recently (interactive)
      {"userPrincipalName":"jane_partner.com#EXT#@host.onmicrosoft.com","mail":"jane@partner.com",
       "createdDateTime":iso(400),"signInActivity":{"lastSignInDateTime":iso(5)}},
      # partner subdomain, no mail -> parse EXT; only non-interactive recent
      {"userPrincipalName":"bob_eu.partner.com#EXT#@host.onmicrosoft.com","mail":None,
       "createdDateTime":iso(400),"signInActivity":{"lastSignInDateTime":iso(300),"lastNonInteractiveSignInDateTime":iso(2)}},
      # lookalike domain must NOT be trusted; underscore in local part
      {"userPrincipalName":"first_last_evilpartner.com#EXT#@host.onmicrosoft.com","mail":None,
       "createdDateTime":iso(400),"signInActivity":{"lastSignInDateTime":iso(200)}},
      # invited 3 days ago, never signed in -> active (not yet stale)
      {"userPrincipalName":"new_vendor.io#EXT#@host.onmicrosoft.com","mail":"new@vendor.io",
       "createdDateTime":iso(3),"signInActivity":{"lastSignInDateTime":None}},
      # old, never signed in -> inactive
      {"userPrincipalName":"old_vendor.io#EXT#@host.onmicrosoft.com","mail":"old@vendor.io",
       "createdDateTime":iso(500),"signInActivity":{}},
    ]
    resp = mock.Mock(); resp.json.return_value = {"value": guests}; resp.raise_for_status.return_value = None
    with mock.patch.object(m, "_get_graph_headers", return_value={}), mock.patch.object(m.requests, "get", return_value=resp) as g:
        r = m.audit_guest_users("t","c","s", trusted_domains=["partner.com"], days_inactive=90)
        sel = g.call_args.kwargs["params"]["$select"]
    assert "signInActivity" in sel and "lastSignInDateTime" not in sel
    emails = lambda k: sorted(x["email"] for x in r[k])
    assert emails("trusted_active") == ["bob_eu.partner.com#EXT#@host.onmicrosoft.com","jane@partner.com"]
    assert emails("untrusted_inactive") == ["first_last_evilpartner.com#EXT#@host.onmicrosoft.com","old@vendor.io"]
    assert emails("untrusted_active") == ["new@vendor.io"]
    assert r["trusted_inactive"] == []
    assert [x["domain"] for x in r["untrusted_inactive"] if "evil" in x["email"]] == ["evilpartner.com"]
