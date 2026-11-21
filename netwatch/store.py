"""Local recordkeeping. The database owner is trusted; this is not an auth service."""
import json
import os
from pathlib import Path
import sqlite3
import time
from contextlib import contextmanager

from . import sources
from .core import Error, canonical


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
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        schema = self.db.execute("PRAGMA user_version").fetchone()[0]
        tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        if schema != 10 and (schema or tables):
            self.db.close()
            raise Error("Incompatible old database; keep it for history and use a new --db path")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS targets(name TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, kind TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, at INTEGER, body TEXT);
            CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, status TEXT, body TEXT, result TEXT);
            PRAGMA user_version=10;
        """)

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

    def event(self, target, kind, body):
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
        row = self.db.execute("SELECT id,at,body FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        return {"id": row["id"], "at": row["at"], **json.loads(row["body"])} if row else None

    def _trim_context(self, name, report):
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

    def _restore_trimmed(self, name, report):
        """When a fresh row is trimmed, its retained copy (same id) comes back.

        The retention merge prefers fresh data; if the trim then drops the fresh row
        because its finding cleared, the previously saved observation must not
        disappear from an already incomplete source.
        """
        context = report.get("context")
        if not isinstance(context, dict):
            return
        old_context = self.latest(name).get("context", {}) if self.latest(name) else {}
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
            self._trim_context(name, report)
            self._restore_trimmed(name, report)
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
