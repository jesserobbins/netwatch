"""Walk a filesystem and classify what it holds, without touching anything.

Two lanes come out of one walk: user-lane venvs (upgradeable, registrable as targets)
and repo-lane checkouts (never targets — they get a `.netwatch` ticket instead). The
classification uses directory structure and file presence only, so `--list` can run on a
root full of unknown checkouts before anything invokes git in them.
"""
import fnmatch
import json
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from . import tickets, userlane, workflow
from .core import Error

SKIP = (".git", "node_modules", ".venv", "__pycache__")
DEFAULT_DEPTH = 4

USER = "user"
REPO = "repo"
UNCLASSIFIED = "unclassified"


@dataclass
class Item:
    path: Path
    lane: str
    evidence: list = field(default_factory=list)


def _is_repo(path: Path) -> bool:
    entry = path / ".git"
    return entry.is_dir() or entry.is_file()


def _user_lane_evidence(path: Path) -> list:
    """A venv is only a candidate when a manager left its own receipt in it.

    `pyvenv.cfg` alone marks an ordinary virtualenv, which netwatch has no kind for and
    must not offer to upgrade; the receipt is what makes the environment the manager's.
    """
    if not (path / "pyvenv.cfg").is_file():
        return []
    if (path / "uv-receipt.toml").is_file():
        return ["uv-receipt.toml", "pyvenv.cfg"]
    if (path / "pipx_metadata.json").is_file():
        return ["pipx_metadata.json", "pyvenv.cfg"]
    return []


def classify(path: Path) -> Item:
    evidence = _user_lane_evidence(path)
    if evidence:
        return Item(path, USER, evidence)
    if _is_repo(path):
        return Item(path, REPO, [".git"])
    if (path / "pyvenv.cfg").is_file():
        # A venv no manager claims: worth showing, never worth offering to upgrade.
        return Item(path, UNCLASSIFIED, ["pyvenv.cfg without a manager receipt"])
    return Item(path, UNCLASSIFIED, [])


def walk(root, depth=DEFAULT_DEPTH, excludes=(), skip=SKIP):
    """Yield items under `root`, stopping at each repo root.

    The stop matters: a repo's contents are read through git by the repo lane, and
    descending would both duplicate that work and walk a tree the operator did not ask
    about. Symlinks to directories are not followed — a scan is not a filesystem crawler.
    """
    root = Path(root).expanduser()
    if not root.is_dir():
        raise NotADirectoryError(str(root))

    def descend(path: Path, level: int):
        try:
            entries = sorted(os.scandir(path), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in skip:
                continue
            if any(fnmatch.fnmatch(entry.name, pattern) for pattern in excludes):
                continue
            if entry.is_symlink() and entry.is_dir(follow_symlinks=False):
                continue
            child = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                item = classify(child)
                if item.evidence:
                    yield item
                    continue
                if level + 1 < depth:
                    yield from descend(child, level + 1)

    return descend(root, 0)


def summary(items) -> str:
    repos = sum(1 for i in items if i.lane == REPO)
    users = sum(1 for i in items if i.lane == USER)
    boundaries = sum(1 for i in items if i.lane == UNCLASSIFIED)
    return "%d repo%s, %d user-lane, %d unclassified" % (
        repos, "" if repos == 1 else "s", users, boundaries)


def _row(item: Item, root: Path) -> tuple:
    try:
        rel = item.path.relative_to(root).as_posix() or "."
    except ValueError:
        rel = str(item.path)
    if item.lane == USER:
        lane, note = "user-lane", "tool enumeration skipped in --list"
    elif item.lane == REPO:
        lane, note = "repo-lane", "ticket, not a target"
    else:
        lane, note = "unclassified", ", ".join(item.evidence) or "no environment markers"
    return rel, lane, note


def list_only(root, depth=DEFAULT_DEPTH, excludes=(), db=None) -> str:
    """Classification table, and nothing else.

    No git, no `gh`, no tool enumeration, and no store: this mode never opens the
    database, so it neither creates a file nor runs the version migration. The `db`
    argument exists only so callers can pass the state path they resolved; it is not
    touched here.
    """
    del db
    root = Path(root).expanduser()
    items = list(walk(root, depth=depth, excludes=excludes))
    lines = [summary(items), ""]
    width = max([len(_row(i, root)[0]) for i in items] + [4])
    for item in items:
        rel, lane, note = _row(item, root)
        lines.append("%-*s  %-11s  %s" % (width, rel, lane, note))
    return "\n".join(lines)


def _origin_url(repo: Path) -> str:
    try:
        return str(tickets.git(repo, "remote", "get-url", "origin")).strip()
    except Exception:
        return ""


def owner_of(url: str) -> tuple:
    """(host, owner) from a git remote URL, without credentials in the answer."""
    if not url:
        return ("", "")
    parsed = urllib.parse.urlsplit(url if "//" in url else "ssh://" + url.replace(":", "/", 1))
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    owner = parts[0] if parts else ""
    return (host, owner)


def owned(repo, handles) -> bool:
    """Ownership is the write gate for automatic tickets: github.com and a known owner."""
    host, owner = owner_of(_origin_url(Path(repo)))
    return host in ("github.com", "www.github.com") and owner.lower() in {h.lower() for h in handles}


def handles_from(names, runner=None) -> set:
    """The configured handle set: the authenticated `gh` login plus `--handle` names.

    One read-only `gh api user` call, and a failure is not fatal: without `gh` the
    explicit handles still work, and a scan without handles simply writes no tickets.
    """
    handles = {n for n in names if n}
    runner = runner or tickets.subprocess.run
    try:
        result = runner(["gh", "api", "user", "--jq", ".login"], capture_output=True, text=True)
    except (OSError, ValueError):
        return handles
    if getattr(result, "returncode", 1) == 0:
        login = (getattr(result, "stdout", "") or "").strip()
        if login:
            handles.add(login)
    return handles


def run(store, root, *, depth=DEFAULT_DEPTH, excludes=(), handles=(), request=None,
        home=None, progress=None, screen=None) -> dict:
    """Walk, classify, ticket the owned repos, persist the run.

    The records are what `--register` indexes into later, so the per-lane ordinals here
    are the numbers the operator will type. One advisory screen covers the whole run:
    every owned repo's packages are deduplicated per (ecosystem, name, version), what the
    hour cache already knows is skipped, and the rest is asked in one batch so a scan of
    a hundred repos costs one or two OSV requests instead of one per package.
    """
    from . import sources
    request = request or sources.fetch
    spelling = Path(root).expanduser()
    root = spelling.resolve()          # run identity is normalized
    # the walk keeps the operator's spelling, so a launcher naming an alias of the same
    # directory can be recognised as inside the venv
    items = list(walk(spelling, depth=depth, excludes=excludes))
    # Progress goes to the caller's own channel (the CLI sends it to stderr), so a scan of a
    # large root says what it is doing instead of going quiet for minutes.
    say = progress or (lambda message: None)
    say("scanning %s (depth %d): %d item%s"
        % (spelling, depth, len(items), "" if len(items) == 1 else "s"))
    asked = {"screen": 0, "detail": 0}

    def counted(url, body=None):
        # Both advisory lanes go through here, so the run can report what it asked: the
        # batch screen posts to querybatch, the detail queries post to query.
        asked["screen" if url == sources.OSV_BATCH else "detail"] += 1
        return request(url, body)

    if screen is None:
        def run_screen(queries):
            return sources.osv_batch(queries, request=counted)
    else:
        def run_screen(queries):
            asked["screen"] += 1
            return screen(queries)

    ordinals = {USER: 0, REPO: 0, UNCLASSIFIED: 0}
    rows, written, skipped, incomplete = [], [], [], []
    repos = []   # owned repos in walk order: (item, detail, payload, packages, reasons)
    for item in items:
        ordinals[item.lane] += 1
        try:
            label = item.path.relative_to(spelling).as_posix() or "."
        except ValueError:
            label = str(item.path)
        say("[%d/%d] %s  %s" % (ordinals[USER] + ordinals[REPO] + ordinals[UNCLASSIFIED],
                               len(items), item.lane, label))
        detail = {"evidence": item.evidence}
        if item.lane == USER:
            row = userlane.describe(item.path)
            if row is None or row.get("kind") is None:
                detail["tool"] = None
                detail["error"] = (row or {}).get("error", "no manager metadata")
                item.lane = UNCLASSIFIED
            else:
                detail.update(tool=row["name"], kind=row["kind"], realpath=row["realpath"],
                              path_as_written=row["path_as_written"], bin_dir=row["bin_dir"],
                              extras=row["extras"],
                              index_options=row.get("index_options_redacted") or [],
                              st_dev=row["st_dev"], st_ino=row["st_ino"])
        if item.lane == REPO:
            is_owned = owned(item.path, handles)
            detail["owned"] = is_owned
            if is_owned:
                say("        reading %s" % label)
                payload, packages, why = tickets.inspect(item.path)
                repos.append((item, detail, payload, packages, why))
            else:
                skipped.append({"path": str(item.path), "reason": "not an owned repo"})
        rows.append((item.lane, ordinals[item.lane], str(Path(item.path).absolute()), detail))
    # One screen for the whole run: the deduplicated union of every owned repo's packages,
    # minus the answers the hour cache already holds. The per-repo passes below then read
    # everything from the cache, so the batch is asked once per scan, not once per checkout.
    union = {}
    for _, _, _, packages, _ in repos:
        for package in packages:
            triple = (package["ecosystem"], package["name"], package["version"])
            union.setdefault(triple, {"package": {"name": package["name"],
                                                   "ecosystem": package["ecosystem"]},
                                       "version": package["version"]})
    keys = ["osv-screen:%s:%s:%s" % triple for triple in union]
    known = store.cached_many(keys, max_age=3600)
    missing = [(key, query) for key, query in zip(keys, union.values()) if key not in known]
    failure = None
    if missing:
        # The screen can be the only slow part of a scan, so it is announced before it
        # runs — a two-request wait must not read as a hang, and a warm run shows the
        # cache holding most of the work.
        say("advisories: screening %d packages (%d already cached)"
            % (len(missing), len(union) - len(missing)))
        try:
            answers = run_screen([query for _, query in missing])
            if len(answers) != len(missing):
                raise Error("advisory screen reply unusable: %d answers for %d packages"
                            % (len(answers), len(missing)))
        except Error as exc:
            # A refused or malformed screen is recorded, never swallowed: every repo that
            # asked reports an incomplete check below instead of reading as clean.
            failure = exc
        else:
            for (key, _), answer in zip(missing, answers):
                store.cached_put(key, answer)

    def repo_screen(queries):
        if failure is not None:
            raise failure
        return run_screen(queries)

    for item, detail, payload, packages, why in repos:
        findings, advise_why = tickets.advisories(packages, request=counted,
                                                  cache=store, screen=repo_screen)
        payload["findings"].extend(findings)
        why.extend(advise_why)
        if why:
            payload["collection"] = "incomplete"
            payload["error"] = "; ".join(why)
        if tickets.should_write(payload, item.path):
            try:
                tickets.write(item.path, tickets.render(payload))
                written.append({"path": str(item.path), "findings": len(payload["findings"])})
                say("        ticket written: %d finding%s"
                    % (len(payload["findings"]),
                       "" if len(payload["findings"]) == 1 else "s"))
                detail["ticket"] = "written"
                store.event(None, "ticket_written",
                            {"repo": str(item.path), "findings": len(payload["findings"])})
            except tickets.Refused as exc:
                detail["ticket"] = "refused: " + str(exc)
        else:
            detail["ticket"] = "left alone"
        if why:
            incomplete.append({"path": str(item.path), "reasons": why})
    if union:
        say("advisories: %d packages screened in %d requests, %d need detail"
            % (len(union), asked["screen"], asked["detail"]))
    counts = {lane: n for lane, n in ordinals.items() if n}
    run_id = store.scan_run(str(root), counts)
    for lane, ordinal, path, detail in rows:
        store.scan_record(run_id, lane, ordinal, path, detail)
    return {"run": run_id, "root": str(root),
            "summary": "scan run %d: %s" % (run_id, summary(items)),
            "counts": counts, "tickets": written, "skipped": skipped,
            "incomplete": incomplete,
            "advisory_requests": {"screen": asked["screen"], "detail": asked["detail"]}}


def report(store, path, *, request=None) -> dict:
    """One ticket, into any repo, on explicit request."""
    from . import sources
    request = request or sources.fetch
    repo = Path(path).expanduser().resolve()
    if not (repo / ".git").exists():
        raise NotADirectoryError(str(repo) + " is not a git checkout")
    payload, why = tickets.collect(repo, request=request, cache=store)
    if not tickets.should_write(payload, repo):
        return {"path": str(repo), "status": "left alone",
                "reasons": why or ["collection produced nothing"]}
    status = tickets.write(repo, tickets.render(payload))
    store.event(None, "ticket_written", {"repo": str(repo), "findings": len(payload["findings"])})
    return {"path": str(repo), "status": status, "findings": payload["findings"],
            "leads": payload["leads"], "collection": payload["collection"], "reasons": why}


MAX_BATCH = 5
LISTING_TIMEOUT = 10


def _resolve_run(store, root, run_id):
    root = str(Path(root).expanduser().resolve())
    if run_id is not None:
        row = store.scan_run_row(run_id)
        if row["root"] != root:
            raise Error("scan run %d belongs to %s, not %s" % (run_id, row["root"], root))
        return run_id
    runs = [r["id"] for r in store.db.execute(
        "SELECT id FROM scan_runs WHERE root=? ORDER BY id DESC", (root,)).fetchall()]
    if not runs:
        raise Error("no scan of %s; run scan first" % root)
    if len(runs) > 1:
        raise Error("ambiguous: pass --run, latest is %d" % runs[0])
    return runs[0]


def register(store, root, indices, *, run_id=None, runner=None):
    """Turn stored scan rows into targets: by index, from the record, never a re-walk.

    The batch is all-or-nothing and the identity checks run inside the write transaction,
    so a transient failure on one item commits nothing and retrying the same command is
    safe.
    """
    if runner is None:
        runner = lambda argv: userlane.adapters.run({"name": "scan", "kind": "uv", "host": "local"},
                                                    argv, timeout=LISTING_TIMEOUT)
    indices = list(indices)
    if not indices:
        raise Error("name at least one index to register")
    if len(indices) > MAX_BATCH:
        raise Error("at most %d indices per registration; split the batch" % MAX_BATCH)
    run = _resolve_run(store, root, run_id)
    rows = store.scan_records(run, lane=USER)
    if not rows:
        raise Error("scan run %d found no user-lane environments" % run)
    chosen = []
    for index in indices:
        if not isinstance(index, int) or index < 1 or index > len(rows):
            raise Error("index %r is not a user-lane row of run %d (1..%d)"
                        % (index, run, len(rows)))
        chosen.append(rows[index - 1])
    registered = []
    with store.transaction():
        verified = []
        for item in chosen:
            detail = item["detail"]
            row = {key: detail.get(key) for key in
                   ("kind", "name", "extras", "bin_dir", "index_options",
                    "realpath", "path_as_written", "st_dev", "st_ino")}
            row["name"] = detail.get("tool") or row["name"]
            verified.append((item, row, userlane.identity(row, runner)))
        blocking = [row for row in store.target_rows()
                    if row["kind"] in (userlane.UVTOOL, userlane.PIPX)
                    and row.get("path") and not row["removed"]
                    and row["state"] not in ("unresolved_path", "identity_mismatch")]
        for item, row, seen in verified:
            for other in blocking:
                if other["name"] != row["name"] and workflow.same_venv(other["path"], row["realpath"]):
                    raise Error("%s already tracks this venv as %s; remove that target first"
                                % (other["name"], other["kind"]))
            # A live target already holding this name is a different registration: suffix
            # rather than rebind it. A removed row is revived in place, which add_target does.
            live = {r["name"]: r for r in store.target_rows() if not r["removed"]}
            wanted, suffix = row["name"], 2
            while wanted in live and not workflow.same_venv(live[wanted].get("path"),
                                                           row["realpath"]):
                wanted = "%s-%d" % (row["name"], suffix)
                suffix += 1
            if wanted != row["name"]:
                taken = row["name"]
                row["name"] = wanted
                registered_note = "suffixed: %s is already tracked by another target" % taken
            else:
                registered_note = None
            body = {"name": row["name"], "kind": row["kind"], "host": "local",
                    "path": row["realpath"], "realpath": row["realpath"],
                    "bin_dir": row["bin_dir"], "extras": row["extras"],
                    "index_options": row.get("index_options_redacted") or [],
                    "registered_from_scan": {"run": run, "ordinal": item["ordinal"],
                                            "path_as_written": row["path_as_written"],
                                            "st_dev": row["st_dev"], "st_ino": row["st_ino"]}}
            store.add_target(row["kind"], body)
            store.event(row["name"], "registered", body)
            registered.append({"note": registered_note,
                               "name": row["name"], "kind": row["kind"],
                               "path": row["realpath"], "extras": row["extras"]})
    return {"run": run, "registered": registered,
            "summary": "registered %d target%s from scan run %d"
                       % (len(registered), "" if len(registered) == 1 else "s", run)}
