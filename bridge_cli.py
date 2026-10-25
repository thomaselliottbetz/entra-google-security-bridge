#!/usr/bin/env python3
"""
Command-line entry point for scheduled runs (cron, Task Scheduler, CI).

    python bridge_cli.py risk-detections --hours-back 24 --min-risk-level medium
    python bridge_cli.py guest-audit --trusted-domain partner.com --days-inactive 90
    python bridge_cli.py oauth-audit --approved-apps-file approved_apps.txt
    python bridge_cli.py ou-sync --ou-mapping-file mapping.json

Secrets are read from the environment, never from arguments (which are visible in process
listings): ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET for Entra commands;
GOOGLE_CREDENTIALS_PATH and GOOGLE_ADMIN_EMAIL for Google commands. Findings are written as
log records (set BRIDGE_LOG_FORMAT=json for JSON lines on stderr).

Exit codes: 0 the run completed; 1 findings were reported and --fail-on-findings was given;
2 usage or configuration error; 3 the run failed or was incomplete (an ERROR was logged, users
could not be audited, or a sync update failed). 3 takes precedence over 1.
"""
import argparse
import json
import logging
import os
import sys

import identity_governance_ms

logger = logging.getLogger("bridge_cli")

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_FAILED = 0, 1, 2, 3


class UsageError(Exception):
    """A missing or invalid setting; reported with the usage exit code."""


class _ErrorCounter(logging.Handler):
    """Counts ERROR-level records so a run that logged a failure cannot exit 0."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.count = 0

    def emit(self, record):
        self.count += 1


def _env(name):
    value = os.environ.get(name)
    if not value:
        raise UsageError(f"{name} must be set")
    return value


def _entra_credentials():
    return _env("ENTRA_TENANT_ID"), _env("ENTRA_CLIENT_ID"), _env("ENTRA_CLIENT_SECRET")


def _google_credentials():
    _env("GOOGLE_ADMIN_EMAIL")  # validated here so a miss is a usage error, not a failed run
    return _env("GOOGLE_CREDENTIALS_PATH")


def _read_lines(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.lstrip().startswith("#")]
    except OSError as e:
        raise UsageError(f"cannot read {path}: {e}")


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise UsageError(f"cannot read JSON from {path}: {e}")


def _domain_map(pairs):
    mapping = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise UsageError(f"--email-domain-map expects FROM=TO, got {pair!r}")
        source, target = pair.split("=", 1)
        mapping[source] = target
    return mapping or None


def _cmd_risk_detections(args):
    detections = identity_governance_ms.get_risk_detections(
        *_entra_credentials(), hours_back=args.hours_back, min_risk_level=args.min_risk_level)
    return len(detections), False


def _cmd_guest_audit(args):
    report = identity_governance_ms.audit_guest_users(
        *_entra_credentials(), trusted_domains=args.trusted_domain or None,
        days_inactive=args.days_inactive)
    findings = sum(len(report[k]) for k in ("untrusted_inactive", "untrusted_active", "trusted_inactive"))
    return findings, False


def _cmd_oauth_audit(args):
    credentials_path = _google_credentials()
    import collaboration_security_google as google  # imported late so Entra commands need no Google libraries

    approved = list(args.approved_app or [])
    if args.approved_apps_file:
        approved += _read_lines(args.approved_apps_file)
    blocked = [*google.DEFAULT_BLOCKED_SCOPES, *args.extra_blocked_scope] if args.extra_blocked_scope else None

    report = google.audit_oauth_tokens(
        credentials_path, blocked_scopes=blocked, approved_apps=approved or None)
    return len(report["high_risk"]), bool(report["errors"])


def _cmd_ou_sync(args):
    credentials_path = _google_credentials()
    entra = _entra_credentials()
    mapping = _read_json(args.ou_mapping_file)
    import collaboration_security_google as google

    filter_criteria = args.filter
    if filter_criteria is None:
        try:
            filter_criteria = google.ou_mapping_filter(mapping)
        except (ValueError, AttributeError, TypeError) as e:
            raise UsageError(f"cannot derive a filter from {args.ou_mapping_file}: {e}")

    result = google.sync_entra_to_google_ou(
        *entra, credentials_path, ou_mapping=mapping, filter_criteria=filter_criteria,
        email_domain_mapping=_domain_map(args.email_domain_map), dry_run=not args.apply)
    # Findings are what a person has to look at. A dry run's planned moves are drift (Google
    # disagrees with Entra); an --apply run has already corrected its moves. Users matched in
    # Entra but missing from Google are never fixed by the sync, so they count either way.
    findings = len(result["skipped"]) + (0 if args.apply else len(result["would_sync"]))
    return findings, bool(result["failed"])


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bridge_cli.py", description="Run entra-google-security-bridge checks from a scheduler.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--fail-on-findings", action="store_true",
                        help="exit 1 when the check reports findings (default: exit 0)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("risk-detections", parents=[common], help="Entra Identity Protection risk detections")
    p.add_argument("--hours-back", type=int, default=24)
    p.add_argument("--min-risk-level", choices=["low", "medium", "high"], default="medium")
    p.set_defaults(run=_cmd_risk_detections)

    p = sub.add_parser("guest-audit", parents=[common], help="Entra B2B guest audit")
    p.add_argument("--trusted-domain", action="append", metavar="DOMAIN",
                   help="repeatable; domains whose guests count as trusted")
    p.add_argument("--days-inactive", type=int, default=90)
    p.set_defaults(run=_cmd_guest_audit)

    p = sub.add_parser("oauth-audit", parents=[common], help="Google Workspace OAuth token audit")
    p.add_argument("--approved-app", action="append", metavar="CLIENT_ID",
                   help="repeatable; OAuth client ID of an approved app")
    p.add_argument("--approved-apps-file", metavar="PATH",
                   help="file with one approved client ID per line (# comments allowed)")
    p.add_argument("--extra-blocked-scope", action="append", metavar="SCOPE",
                   help="repeatable; added to the default blocked scopes")
    p.set_defaults(run=_cmd_oauth_audit)

    p = sub.add_parser("ou-sync", parents=[common], help="Sync Entra attributes to Google OUs (dry run unless --apply)")
    p.add_argument("--ou-mapping-file", required=True, metavar="PATH",
                   help='JSON such as {"officeLocation": {"Seattle": "/Engineering/Seattle"}}')
    p.add_argument("--filter", help="OData $filter for the Entra user query (default: derived from "
                                    "the mapping, so every user returned matches a mapping key)")
    p.add_argument("--email-domain-map", action="append", metavar="FROM=TO",
                   help="repeatable; e.g. @company.com=@company.google.com")
    p.add_argument("--apply", action="store_true", help="make the changes; without it nothing is written")
    p.set_defaults(run=_cmd_ou_sync)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    identity_governance_ms.configure_logging()  # before the counter below, which would make it a no-op
    errors = _ErrorCounter()
    logging.getLogger().addHandler(errors)
    try:
        findings, incomplete = args.run(args)
    except UsageError as e:
        parser.error(str(e))
    except Exception as e:
        logger.error(f"{args.command} failed: {e}", extra={"event": "cli_failed", "command": args.command})
        return EXIT_FAILED
    finally:
        logging.getLogger().removeHandler(errors)

    if errors.count or incomplete:
        return EXIT_FAILED
    if args.fail_on_findings and findings:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
