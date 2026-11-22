"""Local recordkeeping. The database owner is trusted; this is not an auth service."""
import json
import os
from pathlib import Path
import sqlite3
import time
from contextlib import contextmanager

from . import lifecycle, sources
from .core import Error, canonical


SCHEMA_VERSION = 11
BUSY_TIMEOUT_SECONDS = 60


class Store:
    def __init__(self, path):
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise Error("Database must not be a symlink")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
            raise Error("Database must be owned by this user with mode 600")
        # The busy timeout is the waiting side's setting, so it governs how long a
        # concurrent command queues behind a writer rather than failing outright. One
        # registration batch holds the write lock across its listings, so the value has
        # to cover that batch, not just a single statement.
        self.db = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=%d" % (BUSY_TIMEOUT_SECONDS * 1000,))
        self.db.row_factory = sqlite3.Row
        schema = self.db.execute("PRAGMA user_version").fetchone()[0]
        tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        if schema not in (0, 10, SCHEMA_VERSION):
            self.db.close()
            raise Error("Incompatible old database; keep it for history and use a new --db path")
        if schema == 0 and tables:
            # A database written before versioning carries tables but no user_version;
            # guessing what version it is would be a guess about history.
            self.db.close()
            raise Error("Incompatible old database; keep it for history and use a new --db path")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS targets(
                name TEXT PRIMARY KEY, body TEXT NOT NULL,
                kind TEXT, state TEXT, removed INTEGER,
                generation INTEGER, state_seq INTEGER);
            CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, kind TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, at INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, status TEXT, body TEXT, result TEXT);
        """)
        if schema == 10:
            self._migrate_10_to_11()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs(id INTEGER PRIMARY KEY, root TEXT, at INTEGER, counts_json TEXT);
            CREATE TABLE IF NOT EXISTS scan_records(run_id INTEGER, lane TEXT, ordinal INTEGER, item_path TEXT, detail_json TEXT);
            PRAGMA user_version=%d;
        """ % (SCHEMA_VERSION,))
        self.schema_version = self.db.execute("PRAGMA user_version").fetchone()[0]
        self.db_path = path

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def _migrate_10_to_11(self):
        """One transaction, re-checked under the write lock, guarded per column.

        The version gate accepts exactly 10 and exactly 11, so a later stage cannot
        add a column without inventing version 12: everything the lifecycle needs has
        to land here or not at all.
        """
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.db.execute("PRAGMA user_version").fetchone()[0] != 10:
                self.db.rollback()
                return
            present = {row[1] for row in self.db.execute("PRAGMA table_info(targets)")}
            for name, ddl in (
                ("kind", "TEXT"),
                ("state", "TEXT"),
                ("removed", "INTEGER"),
                ("generation", "INTEGER"),
                ("state_seq", "INTEGER"),
            ):
                if name not in present:
                    self.db.execute("ALTER TABLE targets ADD COLUMN %s %s" % (name, ddl))
            for row in self.db.execute("SELECT name, body FROM targets").fetchall():
                try:
                    body = json.loads(row[1])
                except ValueError:
                    body = {}
                self.db.execute(
                    "UPDATE targets SET kind=?, state=? WHERE name=?",
                    (body.get("kind"), "live", row[0]))
            self.db.execute("UPDATE targets SET removed=?, generation=?, state_seq=?", (0, 1, 0))
            self.db.execute("CREATE TABLE IF NOT EXISTS scan_runs(id INTEGER PRIMARY KEY, root TEXT, at INTEGER, counts_json TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS scan_records(run_id INTEGER, lane TEXT, ordinal INTEGER, item_path TEXT, detail_json TEXT)")
            self.db.execute("PRAGMA user_version=%d" % (SCHEMA_VERSION,))
        except BaseException:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def add_target(self, kind, body, *, generation=None):
        """Register or revive a target; the columns carry what plans are gated on.

        A removed name is reusable: reviving resets the row into service and bumps the
        generation, so plans approved before the removal are refused as stale rather
        than applied to a target that was retired in between.
        """
        name = body["name"]
        row = self.db.execute(
            "SELECT removed, generation FROM targets WHERE name=?", (name,)).fetchone()
        if row is None:
            self.db.execute(
                "INSERT INTO targets(name,body,kind,state,removed,generation,state_seq)"
                " VALUES(?,?,?,?,?,?,?)",
                (name, canonical(body), kind, "live", 0, generation or 1, 0))
            return
        revived = int(row["removed"] or 0)
        next_generation = int(row["generation"] or 1) + (1 if revived else 0)
        self.db.execute(
            "UPDATE targets SET body=?, kind=?, removed=0, generation=?, state_seq=state_seq+?"
            " WHERE name=?",
            (canonical(body), kind, next_generation, 1 if revived else 0, name))

    def remove_target(self, name):
        """Retire a target: history and name survive, the row leaves service."""
        row = self.db.execute(
            "SELECT removed, generation FROM targets WHERE name=?", (name,)).fetchone()
        if row is None:
            raise Error("Unknown environment; use add first")
        if int(row["removed"] or 0):
            return 0
        self.db.execute("UPDATE targets SET removed=1, generation=? WHERE name=?",
                        (int(row["generation"] or 1) + 1, name))
        return 1

    def scan_run(self, root, counts) -> int:
        """One row per scan invocation; the id is what `--register` names."""
        cur = self.db.execute("INSERT INTO scan_runs(root, at, counts_json) VALUES(?,?,?)",
                              (root, int(time.time()), canonical(counts)))
        return int(cur.lastrowid)

    def scan_record(self, run_id, lane, ordinal, path, detail):
        self.db.execute(
            "INSERT INTO scan_records(run_id, lane, ordinal, item_path, detail_json) VALUES(?,?,?,?,?)",
            (run_id, lane, ordinal, path, canonical(detail)))

    def scan_run_row(self, run_id):
        row = self.db.execute("SELECT id, root, at, counts_json FROM scan_runs WHERE id=?",
                              (run_id,)).fetchone()
        if row is None:
            raise Error("Unknown scan run; run scan first")
        return {"id": row["id"], "root": row["root"], "at": row["at"],
                "counts": json.loads(row["counts_json"])}

    def scan_records(self, run_id, lane=None):
        sql = "SELECT lane, ordinal, item_path, detail_json FROM scan_records WHERE run_id=?"
        args = [run_id]
        if lane:
            sql += " AND lane=?"
            args.append(lane)
        sql += " ORDER BY lane, ordinal"
        return [{"lane": r["lane"], "ordinal": r["ordinal"], "path": r["item_path"],
                 "detail": json.loads(r["detail_json"])}
                for r in self.db.execute(sql, args)]

    def _constraints_files(self):
        for row in self.db.execute("SELECT body FROM plans"):
            try:
                constraints = json.loads(row["body"]).get("constraints") or {}
            except ValueError:
                continue
            path = constraints.get("path")
            if path:
                yield path

    def expire(self, now=None):
        """Lazy expiry: a proposal nobody acted on stops being applicable.

        Runs in one transaction of its own when a command opens the store, so a plan that
        expired overnight is cleaned by the next thing the operator runs. The plan's
        constraints file goes with it: an approval that can no longer be applied must not
        leave its artifact behind.
        """
        now = int(time.time()) if now is None else int(now)
        expired, doomed = [], []
        with self.transaction():
            for row in self.db.execute("SELECT id, target, body FROM plans WHERE status='proposed'"):
                try:
                    body = json.loads(row["body"])
                except ValueError:
                    continue
                if not lifecycle.expires({"status": "proposed", "at": body.get("expires_at")},
                                         now, ttl_seconds=0):
                    continue
                self.db.execute("UPDATE plans SET status='stale' WHERE id=? AND status='proposed'",
                                (row["id"],))
                self.event(row["target"], "plan_expired", {"plan": row["id"]})
                expired.append(row["id"])
                path = (body.get("constraints") or {}).get("path")
                if path:
                    doomed.append(path)
        for path in doomed:
            try:
                os.unlink(path)
            except OSError:
                pass
        return len(expired)

    def cleanup(self, now=None):
        """Remove what a crashed run left behind, in one transaction that holds the lock.

        Selection and unlink share the lock so a plan commit cannot land between "nothing
        references this file" and its removal.
        """
        now = int(time.time()) if now is None else int(now)
        cutoff = now - 3600
        removed = 0
        referenced = set()
        terminal = set()
        for row in self.db.execute("SELECT status, body FROM plans"):
            try:
                body = json.loads(row["body"])
            except ValueError:
                continue
            path = (body.get("constraints") or {}).get("path")
            if not path:
                continue
            referenced.add(path)
            if row["status"] in ("stale", "resolved"):
                terminal.add(path)
        with self.transaction():
            directory = Path(self.db_path).parent / "constraints" if getattr(self, "db_path", None) else None
            if directory is None:
                directory = Path(".")
            candidates = list(directory.glob("apply-*.tmp")) + list(directory.glob("preview-*.txt"))
            for entry in candidates:
                try:
                    age_ok = entry.stat().st_mtime < cutoff
                except OSError:
                    continue
                stale = str(entry) in terminal
                orphan = entry.name.startswith("preview-") and str(entry) not in referenced and age_ok
                old_temp = entry.name.startswith("apply-") and age_ok
                if not (stale or orphan or old_temp):
                    continue
                try:
                    entry.unlink()
                    removed += 1
                except OSError:
                    continue
        return removed

    def stale_siblings(self, name, *, path=None, venv_match=None):
        """Invalidate every other proposal for this target — or for the same venv."""
        staled = []
        for row in self.db.execute(
                "SELECT id, target, body FROM plans WHERE status='proposed' AND target<>?",
                (name,)).fetchall():
            same = venv_match is not None and path is not None and \
                venv_match(self._body_path(row["body"]), path)
            if same:
                self.db.execute("UPDATE plans SET status='stale' WHERE id=?", (row["id"],))
                staled.append({"plan": row["id"], "target": row["target"]})
        for row in self.db.execute(
                "SELECT id FROM plans WHERE status='proposed' AND target=?", (name,)).fetchall():
            self.db.execute("UPDATE plans SET status='stale' WHERE id=?", (row["id"],))
            staled.append({"plan": row["id"], "target": name})
        return staled

    @staticmethod
    def _body_path(body):
        try:
            target = json.loads(body).get("target") or {}
        except ValueError:
            return None
        return target.get("path") if isinstance(target, dict) else None

    def generation(self, name):
        row = self.db.execute("SELECT generation FROM targets WHERE name=?", (name,)).fetchone()
        return int(row["generation"] or 1) if row else 1

    def event(self, target, kind, body):
        """Every event row carries the generation it was observed at.

        A target that is removed and revived is a different registration with the same
        name; history from before the revival must not read as current coverage, and the
        generation is what tells them apart.
        """
        body = dict(body)
        if target is not None:
            body.setdefault("generation", self.generation(target))
        self.db.execute("INSERT INTO events(target,at,kind,body) VALUES(?,?,?,?)",
                        (target, int(time.time()), kind, canonical(body)))

    def targets(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM targets ORDER BY name")]

    def target(self, name):
        row = self.db.execute("SELECT body FROM targets WHERE name=?", (name,)).fetchone()
        if row is None:
            raise Error("Unknown environment; use add first")
        return json.loads(row[0])

    def latest(self, name):
        """The current report: a row from a previous registration is history, not coverage."""
        current = self.generation(name)
        row = self.db.execute(
            "SELECT id,at,body FROM scans WHERE target=? ORDER BY id DESC LIMIT 1",
            (name,)).fetchone()
        if row is None:
            return None
        body = json.loads(row["body"])
        if int(body.get("generation", 1)) != current:
            return None
        return {"id": row["id"], "at": row["at"], **body}

    def _trim_context(self, name, report, previous):
        """Drop context rows whose subject is no longer a finding.

        A concurrent check can clear a finding between this check's snapshot and this
        save; context fetched only for that finding then describes nothing. Context is
        never applicability evidence, but a report should not carry rows for findings it
        does not contain.
        """
        context = report.get("context")
        if not isinstance(context, dict):
            return
        findings = report["findings"]
        cves = set(sources.advisory_references(findings, cves_only=True))
        references = set(sources.advisory_references(findings))
        for source in ("cve_now", "zero_wire", "pwn_watch"):
            value = context.get(source)
            # Freshly fetched rows whose subject cleared during this check's lifetime are
            # dropped even when the source is incomplete; rows copied forward as retained
            # history (flagged below) stay. cve_now and Zero Wire rows are subject to a
            # finding's CVE; a pwn.watch row matched by package tag stays regardless,
            # because it is a lead about an installed package.
            if not isinstance(value, dict) or not isinstance(value.get("items"), list):
                continue
            if source == "pwn_watch":
                # pwn.watch matches on every advisory id, not only CVEs.
                value["items"] = [item for item in value["items"] if not isinstance(item, dict)
                                  or item.get("retained") or item.get("matched_tags")
                                  or set(item.get("references") or []) & references]
                for item in value["items"]:
                    if isinstance(item, dict) and not item.get("retained"):
                        item["matched_references"] = sorted(set(item.get("references") or []) & references)
            elif source == "cve_now":
                value["items"] = [item for item in value["items"] if not isinstance(item, dict)
                                  or item.get("retained") or item.get("id") in cves]
            else:
                value["items"] = [item for item in value["items"] if not isinstance(item, dict)
                                  or item.get("retained") or set(item.get("references") or []) & cves]
                for item in value["items"]:
                    if isinstance(item, dict) and not item.get("retained"):
                        item["matched_references"] = sorted(set(item.get("references") or []) & cves)

    def _restore_trimmed(self, name, report, previous):
        """When a fresh row is trimmed, its retained copy (same id) comes back.

        The retention merge prefers fresh data; if the trim then drops the fresh row
        because its finding cleared, the previously saved observation must not
        disappear from an already incomplete source.
        """
        context = report.get("context")
        if not isinstance(context, dict):
            return
        old_context = previous.get("context", {}) if previous else {}
        for source, value in context.items():
            # Only a source that fetched this check (incomplete) can have lost a retained
            # row to the trim; a skipped source deliberately clears gone findings'
            # context, and an ok source has no retained copies.
            if not isinstance(value, dict) or value.get("status") != "incomplete" \
                    or not isinstance(value.get("items"), list):
                continue
            present = {item.get("id") for item in value["items"] if isinstance(item, dict)}
            for row in old_context.get(source, {}).get("items", []):
                if row.get("id") not in present:
                    value["items"].append({**row, "retained": True})

    def save_scan(self, name, report):
        report = dict(report)
        report["generation"] = self.generation(name)
        with self.transaction():
            previous = self.latest(name)
            if previous and not report["advisory_check_ok"]:
                report["matcher_revision"] = previous.get("matcher_revision", 1)
            old = {r["key"]: r for r in previous["findings"]} if previous else {}
            new = {r["key"]: r for r in report["findings"]}
            for key, row in new.items():
                row["first_seen"] = old.get(key, {}).get("first_seen", int(time.time()))
                row["last_seen"] = int(time.time())
                semantic = lambda r: {k: v for k, v in r.items() if k not in ("first_seen", "last_seen")}
                if semantic(old.get(key, {})) != semantic(row):
                    self.event(name, "finding_changed" if key in old else "finding_new", row)
            # Only successful evidence collection can clear previous findings.
            if report["advisory_check_ok"]:
                # A scan that ran but skipped packages keeps their prior findings,
                # marked unknown. Everything else — scanned formulae and formulae no
                # longer installed — clears, as it does for every other kind.
                # Retained by (formula, version): a skipped formula that has since been
                # upgraded is a different observation, so its old finding retires.
                retained = (report.get("coverage") or {}).get("retained_versions")
                if retained is not None:
                    # Retained pairs are tap-qualified; a finding without a tap (recorded
                    # before this field existed) falls back to its short package name.
                    pairs = {tuple(pair) for pair in retained}
                    unloadable = {pair[:2] for pair in pairs if len(pair) == 3 and pair[2] == "unloadable"}
                    for key in old.keys() - new.keys():
                        row = old[key]
                        if (row.get("tap") or row["package"], row["installed"]) in pairs \
                                or (row["package"], row["installed"]) in unloadable:
                            new[key] = {**old[key], "state": "unknown",
                                        "reason": "Not scanned by this check; previous finding retained"}
                            if new[key] != old[key]:
                                self.event(name, "finding_changed", new[key])
                removed = old.keys() - new.keys()
                if removed and previous.get("matcher_revision", 1) != report.get("matcher_revision", 1):
                    self.event(name, "findings_reassessed", {"previous_scan": previous["id"], "removed": len(removed),
                               "reason": "Matching rules changed; fewer findings do not imply packages were updated"})
                else:
                    for key in removed:
                        self.event(name, "finding_no_longer_detected", old[key])
            else:
                for key in old.keys() - new.keys():
                    new[key] = {**old[key], "state": "unknown", "reason": "Evidence incomplete; previous finding retained"}
                    if new[key] != old[key]:
                        self.event(name, "finding_changed", new[key])
            report["findings"] = sorted(new.values(), key=lambda r: r["key"])
            old_context = previous.get("context", {}) if previous else {}
            if "context" not in report and old_context:
                report["context"] = {source: {**value, "status": "skipped",
                    "errors": ["Context not requested on this check; showing retained records"]} for source, value in old_context.items()}
            for source, value in report.get("context", {}).items():
                if value["status"] != "ok":
                    current = {r["id"]: r for r in value["items"]} if value["status"] != "skipped" else {}
                    for row in old_context.get(source, {}).get("items", []):
                        current.setdefault(row["id"], {**row, "retained": True})
                    value["items"] = list(current.values())
            self._trim_context(name, report, previous)
            self._restore_trimmed(name, report, previous)
            def context_semantics(context):
                return {source: {"status": value["status"], "errors": value["errors"],
                    "items": [{k: v for k, v in row.items() if k != "fetched_at"} for row in value["items"]]}
                    for source, value in context.items()}
            if context_semantics(old_context) != context_semantics(report.get("context", {})):
                self.event(name, "context_changed", {"context": report.get("context", {})})
            report["updates_observed_at"] = int(time.time())
            if report["update_error"]:
                report["updates"] = previous["updates"] if previous else []
                report["updates_observed_at"] = previous.get("updates_observed_at") if previous else None
            for field in ("updates", "warnings"):
                if not previous or previous.get(field) != report[field]:
                    self.event(name, field + "_changed", {field: report[field]})
            self.db.execute("INSERT INTO scans(target,at,body) VALUES(?,?,?)", (name, int(time.time()), canonical(report)))
            self.event(name, "checked", {"packages": len(report["packages"]), "advisory_check_ok": report["advisory_check_ok"]})
        return self.latest(name)

    def events(self, since=0, target=None):
        rows = self.db.execute("SELECT * FROM events WHERE id>? AND (? IS NULL OR target=?) ORDER BY id LIMIT 1000",
                               (since, target, target)).fetchall()
        return [{**dict(r), "body": json.loads(r["body"])} for r in rows]

    def cached(self, key, loader, *, offline=False, max_age=86400):
        row = self.db.execute("SELECT at,body FROM cache WHERE key=?", (key,)).fetchone()
        age = int(time.time()) - row["at"] if row else None
        if row and max_age > 0 and 0 <= age <= max_age:
            return json.loads(row["body"])
        if offline:
            raise Error("Missing or stale cached advisory evidence; run check without --offline")
        body = loader()
        self.db.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (key, int(time.time()), canonical(body)))
        return body
