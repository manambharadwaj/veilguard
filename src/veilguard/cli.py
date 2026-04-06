"""VeilGuard CLI entrypoint."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

from veilguard import __version__
from veilguard.initialize import init_project
from veilguard.scan import scan
from veilguard.secret_store import SecretStore
from veilguard.status import status
from veilguard.transcript import clean_transcripts
from veilguard.verify import verify
from veilguard.watch import start_watch


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="veilguard",
        description="VeilGuard — secrets out of AI context",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Install protections for detected AI tools")
    p_init.add_argument("dir", nargs="?", default=".", help="Project directory")
    _add_json_flag(p_init)

    p_scan = sub.add_parser("scan", help="Scan for hardcoded credentials")
    p_scan.add_argument("dir", nargs="?", default=".")
    p_scan.add_argument("--include-tests", action="store_true")
    p_scan.add_argument("--fix", action="store_true", help="Show remediation guidance")
    _add_json_flag(p_scan)

    p_status = sub.add_parser("status", help="Show protection status")
    p_status.add_argument("dir", nargs="?", default=".")
    _add_json_flag(p_status)

    p_verify = sub.add_parser("verify", help="Verify env vars vs context exposure")
    p_verify.add_argument("dir", nargs="?", default=".")
    _add_json_flag(p_verify)

    p_clean = sub.add_parser("clean", help="Redact secrets in Claude transcripts")
    p_clean.add_argument("--dry-run", action="store_true")
    p_clean.add_argument("--last", action="store_true", dest="last_session")
    p_clean.add_argument("--path", default=None, help="Target path (file or directory)")

    sub.add_parser("watch", help="Watch transcripts and redact (foreground)")

    p_sec = sub.add_parser("secret", help="Manage secrets in local store")
    sec_sub = p_sec.add_subparsers(dest="sec_cmd", required=True)
    sec_sub.add_parser("list", help="List secret names")
    p_set = sec_sub.add_parser("set", help="Store a secret")
    p_set.add_argument("name")
    p_set.add_argument("value")
    p_get = sec_sub.add_parser("get", help="Print a secret (stdout)")
    p_get.add_argument("name")
    p_rm = sec_sub.add_parser("remove", help="Delete a secret")
    p_rm.add_argument("name")

    p_backend = sub.add_parser("backend", help="Show or set backend type")
    p_backend.add_argument("action", nargs="?", choices=["show", "set"], default="show")
    p_backend.add_argument("type", nargs="?", default=None)

    args = parser.parse_args()

    if args.cmd == "init":
        d = os.path.abspath(args.dir)
        r = init_project(d)
        if args.json_output:
            print(json.dumps(r, indent=2))
        else:
            print(f"  Detected:  {', '.join(r['tools_detected']) or '(none — defaulting to Claude Code)'}")
            print(f"  Configured: {', '.join(r['tools_configured'])}")
            print(f"  Quick-scan findings in config files: {r['secrets_found']}")
            for f in r["files_created"]:
                print(f"  + created {f}")
            for f in r["files_modified"]:
                print(f"  ~ updated {f}")
            print("  Done.")
        return

    if args.cmd == "scan":
        d = os.path.abspath(args.dir)
        findings = scan(d, include_tests=args.include_tests)
        if args.json_output:
            print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))
        else:
            for f in findings:
                print(f"{f.file}:{f.line} [{f.severity}] {f.pattern_name} — {f.preview}")
                if args.fix and f.fix:
                    print(f"  Fix: {f.fix}")
            if not findings:
                print("No credential patterns matched.")
        if findings:
            sys.exit(1)
        return

    if args.cmd == "status":
        d = os.path.abspath(args.dir)
        s = status(d)
        if args.json_output:
            print(json.dumps(s, indent=2))
        else:
            print("Protected:", "yes" if s["is_protected"] else "no")
            print("Hook installed:", s["hook_installed"])
            print("Configured tools:", ", ".join(s["configured_tools"]) or "(none)")
            print("Deny rules:", s["deny_rule_count"])
            print("Scan findings (project):", s["secrets_found"])
            tp = s["transcript_protection"]
            print(
                "Transcripts:", tp["transcript_files"],
                "files; secrets in recent:", tp["transcript_secrets_found"],
            )
            print("Stop hook:", tp["stop_hook_installed"], "| Watch running:", tp["watcher_running"])
        return

    if args.cmd == "verify":
        d = os.path.abspath(args.dir)
        vr = verify(d)
        if args.json_output:
            print(json.dumps(dataclasses.asdict(vr), indent=2))
        else:
            print("Passed:", vr.passed)
            env_set = sum(1 for x in vr.env_vars.values() if x)
            print(f"Env vars with values: {env_set}/{len(vr.env_vars)}")
            print("Exposed in context:", len(vr.exposed_in_context))
            print("Exposed in transcripts:", len(vr.exposed_in_transcripts))
            if vr.exposed_in_context:
                print(json.dumps(vr.exposed_in_context[:20], indent=2))
        if not vr.passed:
            sys.exit(1)
        return

    if args.cmd == "clean":
        cr = clean_transcripts(
            dry_run=args.dry_run,
            target_path=args.path,
            last_session=args.last_session,
        )
        print(
            f"Scanned {cr.files_scanned} file(s); {cr.files_with_secrets} with findings; "
            f"{cr.total_findings} finding(s); redacted {cr.total_redacted}."
        )
        return

    if args.cmd == "watch":
        start_watch()
        return

    if args.cmd == "secret":
        store = SecretStore()
        if args.sec_cmd == "list":
            for n in store.list_secrets():
                print(n)
            return
        if args.sec_cmd == "set":
            store.set_secret(args.name, args.value)
            print("OK")
            return
        if args.sec_cmd == "get":
            v = store.get_secret(args.name)
            if v is None:
                print("Not found", file=sys.stderr)
                sys.exit(1)
            print(v)
            return
        if args.sec_cmd == "remove":
            ok = store.remove_secret(args.name)
            if ok:
                print("Removed")
            else:
                print("Not found", file=sys.stderr)
                sys.exit(1)
            return

    if args.cmd == "backend":
        from veilguard.backends.config import read_backend_config, write_backend_config

        if args.action == "show":
            print(json.dumps(read_backend_config() or {"type": "local"}, indent=2))
            return
        if args.action == "set" and args.type:
            write_backend_config({"type": args.type})
            print("OK")
            return
        parser.error("usage: veilguard backend set <type>")


if __name__ == "__main__":
    main()
