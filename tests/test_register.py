import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from netwatch import cli, scan, store as store_module, userlane

FIXTURES = Path(__file__).parent / "fixtures"


def venv_with(root: Path, name: str, receipt=None, pipx=None, packages=None):
    path = root / name
    (path / "bin").mkdir(parents=True)
    (path / "pyvenv.cfg").write_text("")
    if receipt is not None:
        (path / "uv-receipt.toml").write_bytes((FIXTURES / receipt).read_bytes())
    if pipx is not None:
        meta = json.loads((FIXTURES / pipx).read_text())
        meta["main_package"]["app_paths"][0]["__Path__"] = str(path / "bin" / "luna-doctor")
        (path / "pipx_metadata.json").write_text(json.dumps(meta))
    return path


def listing(packages):
    out = json.dumps([{"name": n, "version": v} for n, v in packages])
    return lambda argv, **kw: out


class DescribeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_uv_receipt_names_the_tool_and_its_bin_dir(self):
        row = userlane.describe(venv_with(self.root, "ruff", receipt="uv-receipt.toml"))
        self.assertEqual(row["kind"], "uvtool")
        self.assertEqual(row["name"], "ruff")
        self.assertEqual(row["extras"], [])
        self.assertEqual(row["index_options"], [])
        self.assertEqual(row["realpath"], os.path.realpath(self.root / "ruff"))

    def test_uv_receipt_extras_are_read(self):
        row = userlane.describe(venv_with(self.root, "mlx", receipt="uv-receipt-extras.toml"))
        self.assertEqual(row["extras"], ["server"])

    def test_pipx_metadata_names_the_tool_and_redacts_index_credentials(self):
        row = userlane.describe(venv_with(self.root, "luna", pipx="pipx-metadata.json"))
        self.assertEqual(row["kind"], "pipx")
        self.assertEqual(row["name"], "luna-doctor")
        self.assertEqual(row["index_options"], ["--index-url", "https://pypi.example/simple"])
        self.assertNotIn("secret", json.dumps(row))

    def test_a_plain_venv_is_not_claimed_by_any_manager(self):
        path = self.root / "plain"
        (path / "bin").mkdir(parents=True)
        (path / "pyvenv.cfg").write_text("")
        self.assertIsNone(userlane.describe(path))

    def test_a_broken_receipt_is_reported_not_raised(self):
        path = venv_with(self.root, "broken", receipt="uv-receipt.toml")
        (path / "uv-receipt.toml").write_text("not toml = =")
        row = userlane.describe(path)
        self.assertIsNone(row["name"])
        self.assertIn("error", row)


class InventoryTests(unittest.TestCase):
    def test_listing_is_parsed_into_packages(self):
        packages = userlane.inventory("/v", runner=listing([("ruff", "0.15.22"), ("click", "8.1.7")]))
        self.assertEqual([p["name"] for p in packages], ["ruff", "click"])
        self.assertEqual(packages[0]["ecosystem"], "PyPI")

    def test_malformed_listing_raises(self):
        with self.assertRaises(userlane.Error):
            userlane.inventory("/v", runner=lambda argv, **kw: "not json")

    def test_the_listing_uses_the_venvs_own_interpreter(self):
        seen = {}
        userlane.inventory("/v", runner=lambda argv, **kw: (seen.setdefault("argv", argv), "[]")[1])
        self.assertEqual(seen["argv"][:5], ["uv", "pip", "list", "--format", "json"])
        self.assertIn("--python", seen["argv"])
        self.assertTrue(seen["argv"][-1].endswith("/v/bin/python"))


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = venv_with(self.root, "ruff", receipt="uv-receipt.toml")
        self.row = userlane.describe(self.venv)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_identity_passes_for_an_unchanged_venv(self):
        seen = userlane.identity(self.row, runner=listing([("ruff", "0.15.22")]))
        self.assertEqual(seen["venv"], self.row["realpath"])
        self.assertEqual([p["name"] for p in seen["packages"]], ["ruff"])

    def test_a_replaced_directory_is_a_rescan_error(self):
        row = dict(self.row, st_ino=self.row["st_ino"] + 1)
        with self.assertRaises(userlane.Error) as caught:
            userlane.identity(row, runner=listing([("ruff", "0.15.22")]))
        self.assertIn("rescan", str(caught.exception))

    def test_a_venv_naming_another_tool_is_a_rescan_error(self):
        row = dict(self.row, name="other")
        with self.assertRaises(userlane.Error):
            userlane.identity(row, runner=listing([("other", "1.0")]))

    def test_a_missing_distribution_is_a_rescan_error(self):
        with self.assertRaises(userlane.Error):
            userlane.identity(self.row, runner=listing([("click", "8.1.7")]))

    def test_a_vanished_path_is_a_rescan_error(self):
        row = dict(self.row, realpath=str(self.root / "gone"))
        with self.assertRaises(userlane.Error):
            userlane.identity(row, runner=listing([("ruff", "0.15.22")]))


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.repo = self.root / "repo"
        (self.repo / ".git").mkdir(parents=True)
        (self.repo / "pyproject.toml").write_text("[project]\nname='x'\n")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.email=a@b", "-c", "user.name=a",
                        "commit", "-qm", "x"], check=True, capture_output=True)
        self.ruff = venv_with(self.tools, "ruff", receipt="uv-receipt.toml")
        self.mlx = venv_with(self.tools, "mlx", receipt="uv-receipt-extras.toml")
        self.runner = listing([("ruff", "0.15.22"), ("mlx-lm", "0.32.0")])

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def scan(self):
        store = store_module.Store(self.state)
        try:
            return scan.run(store, self.root, handles=set(),
                            request=lambda url, body=None: {"vulns": []})
        finally:
            store.close()

    def register(self, indices, **kw):
        store = store_module.Store(self.state)
        try:
            return scan.register(store, self.root, indices, runner=self.runner, **kw)
        finally:
            store.close()

    def test_scan_records_user_lane_rows_with_their_staleness_evidence(self):
        self.scan()
        store = store_module.Store(self.state)
        rows = store.scan_records(1, lane="user")
        store.close()
        self.assertEqual([r["ordinal"] for r in rows], [1, 2])
        self.assertEqual({r["detail"]["tool"] for r in rows}, {"ruff", "mlx-lm"})
        self.assertIn("st_ino", rows[0]["detail"])
        self.assertIn("realpath", rows[0]["detail"])

    def test_register_creates_a_target_from_the_stored_row(self):
        self.scan()
        result = self.register([1])          # walk order is alphabetical: mlx, then ruff
        self.assertEqual([t["name"] for t in result["registered"]], ["mlx-lm"])
        store = store_module.Store(self.state)
        target = store.target("mlx-lm")
        self.assertEqual(target["kind"], "uvtool")
        self.assertEqual(target["extras"], ["server"])
        state = store.db.execute("SELECT state, generation FROM targets WHERE name='mlx-lm'").fetchone()
        self.assertEqual(tuple(state), ("live", 1))
        store.close()

    def test_register_refuses_an_index_that_is_not_a_user_lane_row(self):
        self.scan()
        with self.assertRaises(scan.Error):
            self.register([3])
        with self.assertRaises(scan.Error):
            self.register([1, 99])

    def test_register_refuses_an_ambiguous_run(self):
        self.scan()
        self.scan()
        with self.assertRaises(scan.Error) as caught:
            self.register([1])
        self.assertIn("--run", str(caught.exception))

    def test_register_accepts_an_explicit_run(self):
        self.scan()
        self.scan()
        result = self.register([1], run_id=1)
        self.assertEqual(result["run"], 1)

    def test_register_is_all_or_nothing(self):
        self.scan()
        # the second row's venv is replaced, so its identity check fails after the first passed
        shutil.rmtree(self.ruff)
        with self.assertRaises(userlane.Error):
            self.register([1, 2])
        store = store_module.Store(self.state)
        self.assertEqual(store.targets(), [])
        store.close()

    def test_registering_a_removed_name_revives_it_and_bumps_the_generation(self):
        self.scan()
        self.register([2])                   # ordinal 2 is ruff
        store = store_module.Store(self.state)
        store.remove_target("ruff")
        store.close()
        self.register([2])
        store = store_module.Store(self.state)
        row = store.db.execute("SELECT removed, generation FROM targets WHERE name='ruff'").fetchone()
        self.assertEqual(tuple(row), (0, 3))
        store.close()

    def test_check_on_a_registered_venv_target_runs_the_venv_sequence(self):
        """A registered uvtool target is now observable: check routes to the venv path."""
        self.scan()
        self.register([1])
        store = store_module.Store(self.state)
        try:
            args = cli.parser().parse_args(["check", "mlx-lm"])
            result = cli.dispatch(args, store, lambda t, argv, **kw: self.runner(argv),
                                  None)
        finally:
            store.close()
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0].get("error"))
        self.assertIn("mlx-lm", [p["name"] for p in result[0]["report"]["packages"]])

    def test_register_reports_the_tool_it_registered_by_name(self):
        self.scan()
        result = self.register([1, 2])
        self.assertEqual([t["name"] for t in result["registered"]], ["mlx-lm", "ruff"])
        self.assertEqual(result["summary"], "registered 2 targets from scan run 1")


if __name__ == "__main__":
    unittest.main()


class RegistrationUniquenessTests(unittest.TestCase):
    """One venv, one target: the same `same_venv` predicate the busy query uses."""

    def setUp(self):
        from netwatch import workflow
        self.workflow = workflow
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.venv = venv_with(self.tools, "ruff", receipt="uv-receipt.toml")
        self.runner = listing([("ruff", "0.15.22")])

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_second_target_on_the_same_venv_is_refused(self):
        store = store_module.Store(self.state)
        try:
            scan.run(store, self.root, handles=set(), request=lambda url, body=None: {"vulns": []})
            scan.register(store, self.root, [1], runner=self.runner)
            store.add_target("uvtool", {"name": "ruff-copy", "kind": "uvtool", "host": "local",
                                        "path": str(self.venv / ".")})
            with self.assertRaises(scan.Error) as caught:
                scan.register(store, self.root, [1], runner=self.runner)
            self.assertIn("already tracks this venv", str(caught.exception))
        finally:
            store.close()
