"""Small CLI. Reports are data, not instructions to a privileged agent."""
import argparse
import json
import os
import sys
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime, timezone
from collections import defaultdict
import sqlite3
from pathlib import Path

from . import adapters, scan, sources, userlane, venvflow, workflow
from .core import Error, text
from .store import Store


def parser():
    p = argparse.ArgumentParser(prog="netwatch", description="Track environments, security advisories and human-approved updates.")
    p.add_argument("--db", default=os.path.expanduser("~/.local/state/netwatch/state.db"))
    p.add_argument("--json", action="store_true", help="machine-readable JSON (all strings escaped)")
    p.add_argument("--version", action="version", version="netwatch 0.2.0")
    commands = p.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="register one OS, environment or project; does not connect")
    add.add_argument("name")
    add.add_argument("kind", choices=adapters.KINDS)
    add.add_argument("--host", default="local", help="local or a configured SSH alias/user@host")
    add.add_argument("--path", help="absolute conda prefix or uv/npm project directory")
    commands.add_parser("list", help="list explicitly registered environments")
    check = commands.add_parser("check", help="collect inventory, query/cache advisories and discover updates")
    check.add_argument("name", nargs="?", help="omit to check all registered environments")
    check.add_argument("--all", action="store_true", help="show all finding, context and update rows")
    check.add_argument("--context", action="store_true", help="add cve.now CVE context, pwn.watch incident leads and Cloudflare Zero Wire briefings")
    mode = check.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="use fresh advisory cache; still collects inventory over SSH")
    mode.add_argument("--refresh", action="store_true", help="fetch fresh advisories instead of using the one-hour cache")
    status = commands.add_parser("status", help="query cached reports without connecting")
    status.add_argument("name", nargs="?")
    status.add_argument("--all", action="store_true", help="show all finding, context and update rows")
    history = commands.add_parser("history", help="query events, including changes, failures and update attempts")
    history.add_argument("--name")
    history.add_argument("--since", type=int, default=0, help="event cursor; at most 1000 events per page")
    preview = commands.add_parser("preview", help="show/save environment-wide update commands and observed candidates")
    preview.add_argument("name")
    apply = commands.add_parser("apply", help="approve and run a saved environment-wide update")
    apply.add_argument("plan", type=int)
    apply.add_argument("--yes", action="store_true", help="explicitly approve the scope and commands shown by preview")
    resolve = commands.add_parser("resolve", help="record manual recovery after inspecting an uncertain update")
    resolve.add_argument("plan", type=int)
    resolve.add_argument("--note", required=True)
    commands.add_parser("demo", help="run a temporary simulated workflow; no network or package operations")
    sc = commands.add_parser("scan", help="classify environments under a root; writes tickets into owned repos")
    sc.add_argument("root")
    sc.add_argument("--list", action="store_true",
                    help="classification only: no git, no gh, no tool enumeration, no store")
    sc.add_argument("--depth", type=int, default=scan.DEFAULT_DEPTH, help="how deep to walk (default 4)")
    sc.add_argument("--exclude", action="append", default=[], metavar="PAT", help="skip paths matching PAT (repeatable)")
    sc.add_argument("--register", nargs="+", type=int, metavar="INDEX",
                    help="register these user-lane rows of a stored run as targets")
    sc.add_argument("--run", type=int, help="scan run id (needed when the root has more than one)")
    sc.add_argument("--handle", action="append", default=[], metavar="NAME",
                    help="accept this GitHub owner as yours (repeatable; the gh login is always accepted)")
    tg = commands.add_parser("targets", help="retire a tracked target")
    tsub = tg.add_subparsers(dest="action", required=True)
    trem = tsub.add_parser("remove", help="retire a target; history and name are kept")
    trem.add_argument("name")
    rp = commands.add_parser("report", help="write the .netwatch ticket for one checkout, whatever its owner")
    rp.add_argument("path")
    return p


def status(store, t):
    last = store.db.execute("SELECT kind,at FROM events WHERE target=? AND kind IN ('checked','collection_failed') ORDER BY id DESC LIMIT 1",
                            (t["name"],)).fetchone()
    report = store.latest(t["name"])
    pending = [dict(r) for r in store.db.execute("SELECT id,status,at FROM plans WHERE target=? AND status IN ('proposed','running','needs_attention') ORDER BY id", (t["name"],))]
    return {"target": t, "last_attempt": dict(last) if last else None, "report": report, "pending_updates": pending}


WRITE_COMMANDS = {"add", "check", "preview", "apply", "resolve", "scan", "report", "targets"}


VENV_KINDS = (userlane.UVTOOL, userlane.PIPX)


def one_argv(runner, t, state_dir):
    """The venv kinds take a listing runner: one argv, no SSH, run from the state dir.

    The working directory is pinned there for the same reason the fingerprint hashes the
    configuration files: uv reads configuration from the cwd upward, so inheriting the
    launch directory would let a repo-local `[tool.uv]` shape resolution.
    """
    return lambda argv, **kw: runner({"name": t["name"], "kind": "uv", "host": "local",
                                      "path": str(state_dir)}, argv, **kw)


def state_dir_for(args):
    """Where an approval's artifacts and uv's working directory live: beside the database."""
    return Path(args.db).expanduser().parent


def dispatch(args, store, runner, request):
    if args.command in WRITE_COMMANDS:
        # Expiry and cleanup run in the command's own opening transaction: the next thing
        # the operator runs is the cleaner. status/list/history stay read-only.
        store.expire()
        store.cleanup()
    if args.command == "add":
        t = adapters.target(args.name, args.kind, args.host, args.path)
        with store.transaction():
            if store.db.execute("SELECT 1 FROM targets WHERE name=?", (args.name,)).fetchone():
                raise Error("Environment already exists; use a new name rather than rewriting its history")
            store.add_target(t["kind"], t)
            store.event(args.name, "registered", t)
        return t
    if args.command == "list":
        return store.targets()
    if args.command == "targets" and args.action == "remove":
        t = store.target(args.name)
        # A running or locked update is inspecting this venv right now; retiring the row
        # would orphan the command in flight. The lock must be honoured, not discarded.
        busy = workflow.busy_plan(store, t)
        if busy:
            raise Error("Update %s is running or needs attention; resolve it before "
                        "removing this target" % busy)
        with store.transaction():
            staled = store.stale_siblings(args.name, path=t.get("path"),
                                           venv_match=workflow.same_venv)
            removed = store.remove_target(args.name)
            store.event(args.name, "removed", {"plans_staled": staled})
        return {"name": args.name, "removed": bool(removed), "plans_staled": len(staled)}
    if args.command in ("check", "status"):
        targets = [store.target(args.name)] if args.name else store.targets()
        results, refreshed = [], set()
        for t in targets:
            if args.command == "check":
                try:
                    if t["kind"] in VENV_KINDS:
                        venvflow.check(store, t, runner=one_argv(runner, t, state_dir_for(args)),
                                      request=request)
                    else:
                        workflow.check(store, t, offline=args.offline, refresh=args.refresh, refreshed=refreshed, context=args.context, runner=runner, request=request)
                except Error as exc:
                    results.append({**status(store, t), "error": str(exc)})
                    continue
            results.append(status(store, t))
        return results
    if args.command == "history":
        if args.since < 0:
            raise Error("Cursor must be nonnegative")
        rows = store.events(args.since, args.name)
        return {"events": rows, "next_cursor": rows[-1]["id"] if rows else args.since}
    if args.command == "preview":
        t = store.target(args.name)
        if t["kind"] in VENV_KINDS:
            return venvflow.preview(store, t, runner=one_argv(runner, t, state_dir_for(args)),
                                    request=request, state_dir=state_dir_for(args))
        return workflow.preview(store, t, runner)
    if args.command == "apply":
        plan = store.db.execute("SELECT target FROM plans WHERE id=?", (args.plan,)).fetchone()
        kind = store.target(plan["target"])["kind"] if plan else None
        if kind in VENV_KINDS:
            t = store.target(plan["target"])
            return venvflow.apply(store, args.plan, yes=args.yes,
                                  runner=one_argv(runner, t, state_dir_for(args)),
                                  request=request)
        return workflow.apply(store, args.plan, yes=args.yes, runner=runner, request=request)
    if args.command == "resolve":
        return workflow.resolve(store, args.plan, text(args.note, "recovery note"))
    raise Error("Unknown command")


def display(result, json_output=False, show_all=False):
    # Never emit terminal control sequences to pipes or machine-readable output.
    color = not json_output and sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    console = Console(file=sys.stdout, force_terminal=True, highlight=False, markup=False) if color else None
    wide = console is not None and console.width >= 90
    width = min(console.width, 120) if console else 120
    def table(*headers):
        result = Table(box=box.SIMPLE_HEAD, expand=True, width=width, header_style="bold", border_style="dim", padding=(0, 1))
        for header in headers:
            result.add_column(header, overflow="fold")
        return result
    def emit(value="", style=None):
        if console:
            console.print(Text(value, style=style or ""))
        else:
            print(value)
    if json_output or not (isinstance(result, list) and result and "report" in result[0]):
        encoded = json.dumps(result, ensure_ascii=True, indent=None if json_output else 2)
        if console:
            console.print_json(json=encoded)
        else:
            print(encoded)
        return
    safe = lambda value: json.dumps(str(value), ensure_ascii=True)[1:-1]
    date = lambda at: datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if at is not None else "unknown"
    for item in result:
        t, report = item["target"], item["report"]
        if wide and report:
            affected_count = len({r["package"] for r in report["findings"] if r["state"] == "affected"})
            review_count = len({r["package"] for r in report["findings"] if r["state"] == "unknown"})
            summary = Text()
            summary.append(f"{safe(t['kind'])} on {safe(t.get('host', 'local'))}  |  Checked {date(report['at'])}\n", style="dim")
            for value, style in ((f"{len(report['packages'])} installed", "bold"),
                                 (f"{affected_count} affected", "bold red" if affected_count else "bold"),
                                 (f"{review_count} need review", "bold yellow" if review_count else "bold"),
                                 (f"{len(report['updates'])} available update{'s' if len(report['updates']) != 1 else ''}", "bold cyan")):
                if summary.plain[-1:] != "\n":
                    summary.append("    ")
                summary.append(value, style)
            console.print(Panel(summary, title=Text(safe(t["name"]), style="bold cyan"), title_align="left",
                                border_style="cyan", box=box.ROUNDED, width=width))
        else:
            emit(f"{safe(t['name'])} ({safe(t['kind'])} on {safe(t.get('host', 'local'))})", "bold cyan")
        if item.get("error"):
            emit("  Error: " + safe(item["error"]), "bold red")
        if (item.get("last_attempt") or {}).get("kind") == "collection_failed":
            emit("  Collection failed; showing the previous report.", "bold red")
        if not report:
            emit("  No inventory collected. Run netwatch check " + safe(t["name"]), "yellow")
            continue
        if not wide:
            emit(f"  Checked {date(report['at'])} | {len(report['packages'])} installed packages | {len(report['updates'])} available updates", "dim")
        if not report["advisory_check_ok"]:
            emit("  Advisory check incomplete; retained results need review.", "bold yellow")
        if report["update_error"]:
            emit(f"  Update check: {safe(report['update_error'])}; last observed {date(report.get('updates_observed_at'))}", "yellow")
        for plan in item["pending_updates"]:
            emit(f"  Update plan {plan['id']}: {safe(plan['status'])}", "yellow")
        updates = {u["package"]: u for u in report["updates"]
                   if u.get("ecosystem") in (None, "Homebrew")}
        shortened = False
        for state, label in (("affected", "Affected"), ("unknown", "Needs review")):
            groups = defaultdict(list)
            for row in report["findings"]:
                if row["state"] == state:
                    groups[(row["package"], row["installed"])].append(row)
            if wide and not groups:
                continue
            style = ("bold red" if state == "affected" else "bold yellow") if groups else "bold"
            emit(f"\n{label}: {len(groups)} packages ({sum(map(len, groups.values()))} notices)", style)
            no_fixes = groups and all(not r["fix_versions"] for rows in groups.values() for r in rows)
            if no_fixes:
                emit("  No published fix versions; applicability needs review.", "dim")
            grid = table("Package", "Installed", "Notices", "Reported severity", *([] if no_fixes else ["Reported fixes"])) if wide else None
            ordered = sorted(groups, key=lambda key: (key[0] not in updates, key))
            for key in ordered if show_all else ordered[:5]:
                rows = groups[key]
                ids = sorted({r["advisory"] for r in rows})
                fixes = sorted({v for r in rows for v in r["fix_versions"]})
                count = len(rows)
                severities = sorted({r["severity"] for r in rows if isinstance(r.get("severity"), str) and r["severity"].lower() in ("critical", "high", "medium", "low")})
                ids_text = safe(", ".join(ids if show_all else ids[:3])) + (" ..." if not show_all and len(ids) > 3 else "")
                fixes_text = safe(", ".join(fixes if show_all else fixes[:3]) or "none listed")
                if grid is not None:
                    severity_cell = Text()
                    colors = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan"}
                    for severity in sorted(severities, key=lambda s: list(colors).index(s.lower())):
                        if severity_cell.plain:
                            severity_cell.append(" / ")
                        severity_cell.append(severity.upper(), colors[severity.lower()])
                    cells = [Text(safe(key[0]), style="bold"), Text(safe(key[1]), style="dim"),
                             Text(ids_text), severity_cell if severities else Text("Unknown", style="dim")]
                    if not no_fixes:
                        cells.append(Text(fixes_text))
                    grid.add_row(*cells)
                else:
                    severity = " | reported severity: " + ", ".join(severities) if severities else ""
                    emit(f"  {safe(key[0])} {safe(key[1])}: {count} {'notice' if count == 1 else 'notices'}{safe(severity)}", "bold")
                    emit("    " + ids_text, "dim")
                    emit("    Reported fixes: " + fixes_text)
                shortened |= not show_all and (len(ids) > 3 or len(fixes) > 3)
            if grid is not None:
                console.print(grid)
                if not show_all and len(ordered) > 5:
                    emit(f"  Showing 5 of {len(ordered)} packages.", "dim")
            shortened |= not show_all and len(ordered) > 5
        omitted = sum(e.get("matching", {}).get("fixed_notices_omitted", 0) for e in report.get("evidence", []))
        if omitted:
            emit(f"\n{omitted} historical notices omitted: installed versions meet the tracker fixes.", "dim")
        if report["updates"]:
            emit("\nAvailable updates:", "bold cyan")
            emit("  Repository candidates; not all are security fixes.", "dim")
            versions, by_name = defaultdict(set), defaultdict(set)
            for p in report["packages"]:
                versions[(p.get("ecosystem"), p["name"])].add(p["version"])
                by_name[p["name"]].add(p["version"])

            def installed_for(row):
                # Homebrew keeps formulae and casks apart; a name can appear in both, so a
                # row that names its ecosystem never falls back to the other one's versions.
                found = versions.get((row.get("ecosystem"), row["package"]))
                if found or row.get("ecosystem") is not None:
                    return found or set()
                return by_name[row["package"]]
            # Findings carry the tap-qualified identity; a short name alone must not
            # join a finding to an update row for a replaced formula.
            def identities(state):
                return {r["package"]: {f.get("tap") for f in report["findings"]
                                       if f["package"] == r["package"] and f["state"] == state}
                        for r in report["findings"] if r["state"] == state}
            affected, review = identities("affected"), identities("unknown")
            def has(row, names):
                # Advisories cover formulae, never casks; sorting must agree with the label.
                taps = names.get(row["package"])
                return row.get("ecosystem") in (None, "Homebrew") and taps is not None and (
                    None in taps or row.get("tap") in taps)
            rows = sorted(report["updates"], key=lambda u: (not has(u, affected), not has(u, review),
                                                            u["package"], u.get("ecosystem") or ""))
            # The same package can be upgradable on several architectures; one row per
            # name and ecosystem keeps the ten-row view from spending slots on duplicates.
            grouped, seen_rows = [], set()
            for row in rows:
                marker = (row["package"], row.get("ecosystem"))
                if marker in seen_rows:
                    continue
                seen_rows.add(marker)
                grouped.append(row)
            rows = grouped
            grid = table("Package", "Installed", "Available", "Finding") if wide else None
            for row in rows if show_all else rows[:10]:
                n = row["package"]
                # Advisories cover formulae, never casks, so a same-named cask row must not
                # inherit the formula's marker.
                advisory_applies = row.get("ecosystem") in (None, "Homebrew")
                if advisory_applies and has(row, affected):
                    label, style = " [affected]", "bold red"
                elif advisory_applies and has(row, review):
                    label, style = " [review]", "yellow"
                else:
                    label, style = "", "cyan"
                # A held formula and a cask excluded from the default list are not
                # updates the approved plan will take, so say which one it is.
                state = " [held " + safe(row["held_version"]) + "]" if row.get("held") else (
                    " [not in default upgrade as observed]" if row.get("greedy_only") else "")
                # An update row retained from an earlier report may name a formula that
                # is no longer installed; say so, so a same-named cask row cannot be
                # mistaken for it.
                if row.get("ecosystem") == "Homebrew" and not installed_for(row):
                    state += " [not installed]"
                if row.get("ecosystem") == "Homebrew-cask" and (
                        any(p["name"] == row["package"] and p["ecosystem"] == "Homebrew"
                            for p in report["packages"])
                        or any(f["package"] == row["package"] for f in report["findings"])):
                    state += " [cask]"
                installed = safe(', '.join(sorted(installed_for(row))) or '?')
                candidate = safe(row.get('candidate') or 'unknown')
                if grid is not None:
                    grid.add_row(Text(safe(n), style="bold"), Text(installed, style="dim"), Text(candidate, style="bold cyan"),
                                 Text((label + state).strip() or "No matching advisory",
                                      style=style if label or row.get("held") else "dim"))
                else:
                    emit(f"  {safe(n)}: {installed} -> {candidate}{label}{state}", style)
            if grid is not None:
                console.print(grid)
                if not show_all and len(rows) > 10:
                    emit(f"  Showing 10 of {len(rows)} updates.", "dim")
            shortened |= not show_all and len(rows) > 10
        for source, label in (("cve_now", "cve.now CVE context"), ("pwn_watch", "pwn.watch incident leads"),
                              ("zero_wire", "Cloudflare Zero Wire briefings")):
            context = report.get("context", {}).get(source)
            if context is None:
                continue
            rows = context["items"]
            emit(f"\n{label}: {len(rows)} ({safe(context['status'])}; not applicability evidence)", "bold yellow")
            for error in context["errors"]:
                emit("  " + safe(error), "yellow")
            for row in rows if show_all else rows[:5]:
                retained = " [retained; not refreshed]" if row.get("retained") else ""
                emit(f"  {safe(row['id'])}{retained} | observed {date(row.get('fetched_at'))}", "bold")
                if source == "cve_now":
                    signals = row["signals"]
                    labels = ["CISA KEV listed"] if signals["kev"] is not None else []
                    if signals["epssReached"] is not None:
                        labels.append("EPSS threshold reached (not a current score)")
                    if signals["public_exploit_sources"]:
                        labels.append("public exploit references")
                    emit("    Source status: " + safe(row["status"]) + (" | " + "; ".join(labels) if labels else " | no exploitation signals reported; not proof of safety"))
                    if row["summary"]:
                        summary = row["summary"]
                        emit(f"    Model summary ({safe(summary['model'])}; CC-BY-4.0): {safe(summary['text'])}")
                elif source == "zero_wire":
                    emit("    " + safe(row["title"]))
                    emit(f"    Source priority: {safe(row['priority'])}; updated {safe(row['updated_at'])}; matched CVEs: {safe(', '.join(row['matched_references']))}")
                else:
                    emit("    " + safe(row["title"]))
                    emit(f"    Source patch status: {safe(row['patch_status'])}; advisory links: {safe(', '.join(row['matched_references']) or 'none')}; tags: {safe(', '.join(row['matched_tags']) or 'none')}")
                emit("    " + safe(row["url"]), "dim")
            if not show_all and len(rows) > 5:
                emit(f"  Showing 5 of {len(rows)} context records.", "dim")
                shortened = True
        for warning in report["warnings"]:
            if wide:
                console.print(Panel(Text(safe(warning.removeprefix("Coverage: "))), title="Coverage" if warning.startswith("Coverage:") else "Check note",
                                    title_align="left", border_style="yellow", box=box.ROUNDED, width=width))
            else:
                emit("\n" + safe(warning), "yellow")
        if shortened:
            emit(f"\nAll rows: netwatch status {safe(t['name'])} --all", "dim")
        emit(f"Full records: netwatch --json status {safe(t['name'])}\n", "dim")


def main(argv=None, *, runner=adapters.run, request=sources.fetch):
    args = parser().parse_args(argv)
    store = None
    try:
        if args.command == "demo":
            from .demo import demo
            result = demo()
        elif args.command == "scan" and args.list:
            Console().print(scan.list_only(args.root, depth=args.depth,
                                           excludes=tuple(args.exclude), db=args.db))
            return 0
        elif args.command == "scan" and args.register:
            store = Store(args.db)
            store.expire()
            store.cleanup()
            result = scan.register(store, args.root, args.register, run_id=args.run)
            Console().print(result["summary"])
            for row in result["registered"]:
                Console().print("registered: %s (%s) %s" % (row["name"], row["kind"], row["path"]))
            return 0
        elif args.command == "scan":
            store = Store(args.db)
            store.expire()
            store.cleanup()
            handles = scan.handles_from(args.handle)
            result = scan.run(store, args.root, depth=args.depth,
                              excludes=tuple(args.exclude), handles=handles, request=request)
            Console().print(result["summary"])
            for row in result["tickets"]:
                Console().print("ticket: %s (%d findings)" % (row["path"], row["findings"]))
            for row in result["skipped"]:
                Console().print("skipped: %s (%s)" % (row["path"], row["reason"]))
            return 0
        elif args.command == "report":
            store = Store(args.db)
            store.expire()
            store.cleanup()
            outcome = scan.report(store, args.path, request=request)
            if outcome["status"] != "written":
                Console().print("%s: %s" % (outcome["path"], outcome["status"]))
            else:
                Console().print("%s: ticket %s, %d findings" % (
                    outcome["path"], outcome["status"], len(outcome["findings"])))
            return 0
        else:
            store = Store(args.db)
            result = dispatch(args, store, runner, request)
        display(result, args.json, show_all=getattr(args, "all", False))
        def needs_attention(row):
            """A row without a report is unfinished coverage, so it counts too."""
            report = row.get("report")
            if row.get("error") or not report:
                return True
            if not report["advisory_check_ok"] or report["update_error"]:
                return True
            return any(c["status"] == "incomplete" for c in report.get("context", {}).values())

        if args.command == "check" and any(needs_attention(r) for r in result):
            return 1
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError, sqlite3.Error) as exc:
        error = {"error": str(exc) if isinstance(exc, Error) else "Operation failed; check configuration and history"}
        if store:
            try:
                store.event(getattr(args, "name", None), "command_failed", {"command": args.command, "error_type": type(exc).__name__})
            except sqlite3.Error:
                error["logging_error"] = "Could not record failure; inspect storage and any running update"
        display(error, True)
        return 1
    except KeyboardInterrupt:
        display({"error": "Interrupted; inspect history before retrying an update"}, True)
        return 130
    finally:
        if store:
            store.close()
