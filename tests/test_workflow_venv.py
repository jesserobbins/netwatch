import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from netwatch import cli, store as store_module, workflow
from netwatch.core import canonical


def two_spellings(root: Path):
    venv = root / "tools" / "ruff"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("")
    return str(venv), str(root / "tools" / "." / "ruff")


class SameVenvTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.a, self.b = two_spellings(self.root)

    def test_two_spellings_of_one_directory_are_the_same_venv(self):
        self.assertTrue(workflow.same_venv(self.a, self.b))

    def test_a_hard_link_to_the_directory_counting_as_the_same_venv(self):
        other = self.root / "alias"
        os.symlink(self.a, other)
        self.assertTrue(workflow.same_venv(self.a, str(other)))

    def test_different_directories_are_not_the_same_venv(self):
        other = self.root / "tools" / "other"
        other.mkdir()
        self.assertFalse(workflow.same_venv(self.a, str(other)))

    def test_a_missing_path_is_never_the_same_venv(self):
        self.assertFalse(workflow.same_venv(self.a, None))
        self.assertFalse(workflow.same_venv(str(self.root / "gone"), self.a))


class BusyQueryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        self.a, self.b = two_spellings(self.root)
        self.store = store_module.Store(self.state)
        self.store.add_target("uv", {"name": "ruff", "kind": "uv", "host": "local", "path": self.a})
        self.store.add_target("uv", {"name": "twin", "kind": "uv", "host": "local", "path": self.b})

    def tearDown(self):
        self.store.close()

    def plan(self, target, status):
        body = {"target": {"name": target, "path": self.a}, "commands": [["true"]]}
        cur = self.store.db.execute(
            "INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
            (target, int(time.time()), status, canonical(body)))
        return cur.lastrowid

    def test_a_plan_on_the_same_venv_blocks_a_sibling_target(self):
        self.plan("twin", "running")
        self.assertIsNotNone(workflow.busy_plan(self.store, self.store.target("ruff")))

    def test_a_plan_on_an_unrelated_venv_does_not_block(self):
        other = self.root / "elsewhere"
        other.mkdir()
        self.store.add_target("uv", {"name": "other", "kind": "uv", "host": "local", "path": str(other)})
        self.plan("other", "running")
        self.assertIsNone(workflow.busy_plan(self.store, self.store.target("ruff")))


class ExpiryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.root / "state.db")
        self.store.add_target("uv", {"name": "ruff", "kind": "uv", "host": "local", "path": "/v"})

    def tearDown(self):
        self.store.close()

    def plan(self, expires_at, status="proposed"):
        body = {"target": {"name": "ruff", "path": "/v"}, "commands": [["true"]], "expires_at": expires_at}
        cur = self.store.db.execute("INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
                                    ("ruff", int(time.time()), status, canonical(body)))
        return cur.lastrowid

    def status(self, plan_id):
        return self.store.db.execute("SELECT status FROM plans WHERE id=?", (plan_id,)).fetchone()[0]

    def test_an_expired_proposal_goes_stale_and_is_recorded(self):
        plan_id = self.plan(int(time.time()) - 60)
        self.assertEqual(self.store.expire(), 1)
        self.assertEqual(self.status(plan_id), "stale")
        kinds = [r[0] for r in self.store.db.execute("SELECT kind FROM events WHERE target='ruff'")]
        self.assertIn("plan_expired", kinds)

    def test_a_live_proposal_is_untouched(self):
        plan_id = self.plan(int(time.time()) + 3600)
        self.assertEqual(self.store.expire(), 0)
        self.assertEqual(self.status(plan_id), "proposed")

    def test_expiry_never_reopens_or_reclassifies_an_attempted_plan(self):
        plan_id = self.plan(int(time.time()) - 60, status="needs_attention")
        self.assertEqual(self.store.expire(), 0)
        self.assertEqual(self.status(plan_id), "needs_attention")


class TargetsRemoveTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.root / "state.db")
        self.a, self.b = two_spellings(self.root)
        self.store.add_target("uv", {"name": "ruff", "kind": "uv", "host": "local", "path": self.a})
        self.store.add_target("uv", {"name": "twin", "kind": "uv", "host": "local", "path": self.b})

    def tearDown(self):
        self.store.close()

    def plan(self, target):
        body = {"target": {"name": target, "path": self.a}, "commands": [["true"]], "expires_at": int(time.time()) + 3600}
        cur = self.store.db.execute("INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
                                    (target, int(time.time()), "proposed", canonical(body)))
        return cur.lastrowid

    def test_remove_retires_the_row_and_stales_plans_on_the_same_venv(self):
        mine, twin = self.plan("ruff"), self.plan("twin")
        args = cli.parser().parse_args(["targets", "remove", "ruff"])
        result = cli.dispatch(args, self.store, None, None)
        self.assertTrue(result["removed"])
        self.assertEqual(self.store.db.execute("SELECT removed FROM targets WHERE name='ruff'").fetchone()[0], 1)
        statuses = {r[0] for r in self.store.db.execute("SELECT status FROM plans WHERE id IN (?,?)", (mine, twin))}
        self.assertEqual(statuses, {"stale"})

    def test_the_removed_name_is_reusable(self):
        cli.dispatch(cli.parser().parse_args(["targets", "remove", "ruff"]), self.store, None, None)
        self.store.add_target("uv", {"name": "ruff", "kind": "uv", "host": "local", "path": self.a})
        row = self.store.db.execute("SELECT removed, generation FROM targets WHERE name='ruff'").fetchone()
        self.assertEqual(tuple(row), (0, 3))

    def test_removing_an_unknown_target_is_an_error(self):
        with self.assertRaises(Exception):
            cli.dispatch(cli.parser().parse_args(["targets", "remove", "nope"]), self.store, None, None)


class ReadOnlyCommandsStayReadOnlyTests(unittest.TestCase):
    def test_status_and_list_do_not_expire_anything(self):
        root = Path(tempfile.mkdtemp())
        store = store_module.Store(root / "state.db")
        store.add_target("uv", {"name": "ruff", "kind": "uv", "host": "local", "path": "/v"})
        body = {"target": {"name": "ruff", "path": "/v"}, "commands": [["true"]],
                "expires_at": int(time.time()) - 60}
        store.db.execute("INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
                         ("ruff", int(time.time()), "proposed", canonical(body)))
        for command in (["status"], ["list"], ["history"]):
            cli.dispatch(cli.parser().parse_args(command), store, None, None)
        self.assertEqual(store.db.execute("SELECT status FROM plans").fetchone()[0], "proposed")
        store.close()


if __name__ == "__main__":
    unittest.main()


class ApplyRefusesASharedVenvTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.root / "state.db")
        self.a, self.b = two_spellings(self.root)
        self.store.add_target("uv", {"name": "ruff", "kind": "uv", "host": "local", "path": self.a})
        self.store.add_target("uv", {"name": "twin", "kind": "uv", "host": "local", "path": self.b})

    def tearDown(self):
        self.store.close()

    def test_apply_refuses_when_another_target_tracks_the_same_venv(self):
        body = {"target": self.store.target("ruff"), "commands": [["true"]],
                "inventory_digest": "x", "expires_at": int(time.time()) + 3600}
        plan_id = self.store.db.execute(
            "INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
            ("ruff", int(time.time()), "proposed", canonical(body))).lastrowid
        with self.assertRaises(Exception):
            workflow.apply(self.store, plan_id, yes=True)


class ResolveStalingTests(unittest.TestCase):
    """A crashed venv install may have changed what a twin target's plan observed."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.root / "state.db")
        self.a, self.b = two_spellings(self.root)
        self.store.add_target("uvtool", {"name": "ruff", "kind": "uvtool", "host": "local",
                                         "path": self.a, "realpath": self.a})
        self.store.add_target("uvtool", {"name": "twin", "kind": "uvtool", "host": "local",
                                         "path": self.b, "realpath": self.b})

    def tearDown(self):
        self.store.close()

    def plan(self, target, status="proposed", path=None):
        body = {"target": {"name": target, "path": path or self.a}, "commands": [["true"]],
                "expires_at": int(time.time()) + 3600}
        return self.store.db.execute(
            "INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
            (target, int(time.time()), status, canonical(body))).lastrowid

    def status(self, plan_id):
        return self.store.db.execute("SELECT status FROM plans WHERE id=?", (plan_id,)).fetchone()[0]

    def test_resolve_stales_a_sibling_plan_on_the_same_venv(self):
        crashed = self.plan("ruff", status="needs_attention")
        twin = self.plan("twin")
        workflow.resolve(self.store, crashed, "inspected; no process running")
        self.assertEqual(self.status(crashed), "resolved")
        self.assertEqual(self.status(twin), "stale")

    def test_resolve_leaves_an_unrelated_targets_plan_alone(self):
        other = self.root / "elsewhere"
        other.mkdir()
        self.store.add_target("uvtool", {"name": "other", "kind": "uvtool", "host": "local",
                                         "path": str(other), "realpath": str(other)})
        crashed = self.plan("ruff", status="needs_attention")
        unrelated = self.plan("other", path=str(other))
        workflow.resolve(self.store, crashed, "inspected")
        self.assertEqual(self.status(unrelated), "proposed")
