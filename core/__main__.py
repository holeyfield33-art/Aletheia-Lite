"""aletheia-light command-line entry point.

Subcommands
-----------
    check      run one request through the full pipeline and print the verdict
    verify     verify the audit-log hash chain integrity
    dashboard  serve the local decision dashboard (FastAPI/uvicorn)

The ``check`` path is the single end-to-end wire-up: canonicalization ->
sandbox / symbolic-narrowing (inside Scout) -> Scout -> Nitpicker -> Judge ->
guards / confused-deputy / chain-signing / audit -> a decision + signed receipt.
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import load_config
from .logging import configure
from .manifest import ManifestError, default_manifest, load_manifest
from .pipeline import AuditPipeline


def _build_pipeline(args) -> AuditPipeline:
    cfg = load_config()
    cfg.ensure_dirs()
    configure(cfg.log_level)
    manifest = default_manifest()
    manifest_path = args.manifest or cfg.manifest_path
    if manifest_path:
        try:
            manifest = load_manifest(manifest_path)
        except ManifestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
    return AuditPipeline(config=cfg, manifest=manifest)


def _cmd_check(args) -> int:
    pipeline = _build_pipeline(args)
    metadata: dict = {}
    if args.on_behalf_of:
        metadata["on_behalf_of"] = args.on_behalf_of
    if args.declare:
        metadata["declared_resources"] = args.declare
    outcome = pipeline.submit(
        action=args.action,
        agent=args.agent,
        resources=args.resource,
        metadata=metadata,
    )
    if args.json:
        print(json.dumps(outcome.to_dict(), indent=2))
    else:
        print(f"verdict : {outcome.verdict.value}")
        print(f"receipt : {outcome.receipt['receipt_id']} (signed by {outcome.receipt['signer_source']})")
        if outcome.receipt["violations"]:
            print("violations:")
            for v in outcome.receipt["violations"]:
                print(f"  - {v.get('source', v.get('kind', '?'))}: {v.get('detail')}")
    pipeline.close()
    # non-zero exit when blocked so it composes in shell pipelines
    return 0 if outcome.allowed else 1


def _cmd_verify(args) -> int:
    pipeline = _build_pipeline(args)
    ok, detail = pipeline.audit.verify_integrity()
    print(f"audit chain: {'OK' if ok else 'BROKEN'} — {detail}")
    pipeline.close()
    return 0 if ok else 1


def _cmd_dashboard(args) -> int:
    import uvicorn

    from .decisions import DecisionStore
    from dashboard.server import create_app

    cfg = load_config()
    cfg.ensure_dirs()
    if not cfg.dashboard_token:
        print(
            "refusing to start: set ALETHEIA_DASHBOARD_TOKEN before serving the dashboard",
            file=sys.stderr,
        )
        return 2
    store = DecisionStore(cfg.decisions_db_path)
    app = create_app(store, config=cfg)
    uvicorn.run(app, host=cfg.dashboard_host, port=cfg.dashboard_port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aletheia-light", description=__doc__)
    parser.add_argument("--manifest", help="path to a signed policy manifest")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="evaluate one request")
    p_check.add_argument("action", help="the request / action text to evaluate")
    p_check.add_argument("--agent", default="anonymous")
    p_check.add_argument("--resource", action="append", default=[], help="requested resource (repeatable)")
    p_check.add_argument("--declare", action="append", default=[], help="declared resource (repeatable)")
    p_check.add_argument("--on-behalf-of", dest="on_behalf_of", default=None)
    p_check.add_argument("--json", action="store_true", help="emit the full outcome as JSON")
    p_check.set_defaults(func=_cmd_check)

    p_verify = sub.add_parser("verify", help="verify audit-log integrity")
    p_verify.set_defaults(func=_cmd_verify)

    p_dash = sub.add_parser("dashboard", help="serve the decision dashboard")
    p_dash.set_defaults(func=_cmd_dashboard)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
