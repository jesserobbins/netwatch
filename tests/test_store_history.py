import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from netwatch import store as store_module
from netwatch.core import canonical


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.root / "state.db")
        self.store.add_target("uv", {"name": "t", "kind": "uv", "host": "local", "path": "/v"})

    def tearDown(self):
        self.store.close()

    def report(self):
        return {"target": {"name": "t", "kind": "uv", "host": "local", "path": "/v"},
                "packages": [], "findings": [], "updates": [], "warnings": [],
                "advisory_check_ok": True, "evidence": [], "update_error": None,
                "coverage": None, "matcher_revision": 1}

    def test_every_event_row_carries_the_generation(self):
        self.store.event("t", "checked", {"x": 1})
        body = json.loads(self.store.db.execute("SELECT body FROM events").fetchone()[0])
        self.assertEqual(body["generation"], 1)

    def test_a_scan_report_carries_the_generation(self):
        self.store.save_scan("t", self.report())
        body = json.loads(self.store.db.execute("SELECT body FROM scans").fetchone()[0])
        self.assertEqual(body["generation"], 1)

    def test_a_plan_result_carries_the_generation(self):
        self.store.db.execute("INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
                              ("t", 1, "proposed", canonical({"target": {"name": "t"}})))
        self.store.db.execute("UPDATE plans SET result=?", (canonical({"ok": True}),))
        rows = self.store.db.execute("SELECT generation FROM targets").fetchone()
        self.assertEqual(rows[0], 1)

    def test_history_from_before_a_revival_is_not_current_coverage(self):
        self.store.save_scan("t", self.report())
        self.assertIsNotNone(self.store.latest("t"))
        self.store.remove_target("t")
        self.store.add_target("uv", {"name": "t", "kind": "uv", "host": "local", "path": "/v"})
        # generation is now higher: the pre-removal report is history, not coverage
        self.assertIsNone(self.store.latest("t"))
        self.store.save_scan("t", self.report())
        self.assertIsNotNone(self.store.latest("t"))
        self.assertEqual(self.store.latest("t")["generation"], self.store.generation("t"))


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state"
        (self.state / "constraints").mkdir(parents=True)
        self.store = store_module.Store(self.state / "state.db")
        self.store.add_target("uv", {"name": "t", "kind": "uv", "host": "local", "path": "/v"})

    def tearDown(self):
        self.store.close()

    def plan(self, status="proposed", expires_at=None):
        nonce = "abc123"
        path = self.state / "constraints" / ("preview-%s.txt" % nonce)
        path.write_text("t==1\n")
        body = {"target": {"name": "t", "path": "/v"}, "commands": [["true"]],
                "constraints": {"path": str(path), "digest": "d", "bytes": "t==1\n"},
                "expires_at": expires_at if expires_at is not None else int(time.time()) + 3600}
        cur = self.store.db.execute("INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
                                    ("t", int(time.time()), status, canonical(body)))
        return cur.lastrowid, path

    def test_expiry_deletes_the_plans_constraints_file(self):
        _, path = self.plan(expires_at=int(time.time()) - 60)
        self.assertEqual(self.store.expire(), 1)
        self.assertFalse(path.exists())

    def test_expiry_leaves_a_live_plans_file_alone(self):
        _, path = self.plan()
        self.store.expire()
        self.assertTrue(path.exists())

    def test_cleanup_removes_stale_apply_temps(self):
        temp = self.state / "constraints" / "apply-1-abcd.tmp"
        temp.write_text("x")
        os.utime(temp, (time.time() - 7200,) * 2)
        self.store.cleanup()
        self.assertFalse(temp.exists())

    def test_cleanup_removes_unreferenced_preview_files_only_when_old(self):
        orphan = self.state / "constraints" / "preview-deadbeef.txt"
        orphan.write_text("x")
        os.utime(orphan, (time.time() - 7200,) * 2)
        referenced, _ = self.plan()
        fresh_orphan = self.state / "constraints" / "preview-fresh.txt"
        fresh_orphan.write_text("x")
        self.store.cleanup()
        self.assertFalse(orphan.exists())
        self.assertTrue(fresh_orphan.exists())
        self.assertEqual(len([p for p in (self.state / "constraints").glob("preview-*.txt")]), 2)

    def test_cleanup_removes_a_stale_or_resolved_plans_file(self):
        _, path = self.plan(status="stale")
        self.store.cleanup()
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
