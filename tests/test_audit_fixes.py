"""Tests for the paths the second audit found unexercised."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from netwatch import pins, probe, store as store_module, userlane, venvflow

FIXTURES = Path(__file__).parent / "fixtures"


def dist_dir(venv: Path, name: str, version="1.0"):
    site = venv / "lib" / "python3.12" / "site-packages"
    dist = site / ("%s-%s.dist-info" % (name, version))
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n"
                                   % (name, version))
    return dist


def make_venv(root: Path, name="tool", requires=(), direct_url=None, receipt=None):
    venv = root / "tools" / name
    (venv / "bin").mkdir(parents=True, exist_ok=True)
    if not (venv / "bin" / "python").exists():
        (venv / "bin" / "python").symlink_to(sys.executable)
    (venv / "pyvenv.cfg").write_text("")
    body = "Metadata-Version: 2.1\nName: %s\nVersion: 1.0\n" % name
    body += "".join("Requires-Dist: %s\n" % r for r in requires)
    dist = dist_dir(venv, name)
    (dist / "METADATA").write_text(body)
    if direct_url is not None:
        (dist / "direct_url.json").write_text(json.dumps(direct_url))
    text = (FIXTURES / "uv-receipt.toml").read_text().replace('"ruff"', '"%s"' % name)
    (venv / "uv-receipt.toml").write_text(receipt if receipt is not None else text)
    return venv


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state"
        self.venv = make_venv(self.root)
        self.store = store_module.Store(self.state / "state.db")
        self.store.add_target("uvtool", {"name": "tool", "kind": "uvtool", "host": "local",
                                         "path": os.path.realpath(self.venv),
                                         "realpath": os.path.realpath(self.venv)})
        self.t = self.store.target("tool")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def no_network(self, url, body=None):
        return {"vulns": []}

    def runner(self, latest="2.0", listing=None, name="tool"):
        rows = listing if listing is not None else [{"name": name, "version": "1.0"}]
        def run(argv, **kw):
            if "--outdated" in argv:
                return json.dumps([{"name": name, "version": "1.0",
                                    "latest_version": latest}])
            if "check" in argv:
                return "No broken requirements found."
            return json.dumps(rows)
        return run


class ConstraintsArtifactTests(Base):
    def test_a_retained_bound_reaches_the_constraints_file(self):
        """Selecting under a bound is not constraining the install to it."""
        requiring = dist_dir(self.venv, "requirer")
        (requiring / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: requirer\nVersion: 9.0\n"
            "Requires-Dist: other<2\n")
        listing = [{"name": "tool", "version": "1.0"}, {"name": "requirer", "version": "9.0"}]

        def run(argv, **kw):
            if "--outdated" in argv:
                return json.dumps([{"name": "tool", "version": "1.0", "latest_version": "2.0"},
                                   {"name": "other", "version": "1.0", "latest_version": "3.0"}])
            if "check" in argv:
                return "No broken requirements found."
            return json.dumps(listing)

        result = venvflow.preview(self.store, self.t, runner=run,
                                  request=self.no_network, state_dir=self.state)
        body = Path(result["constraints"]["path"]).read_text()
        # the bound that blocked `other` is in the artifact the installer is given
        self.assertIn("other<2", body)
        self.assertIn("tool==2.0", body)
        self.assertNotIn("other==", body)

    def test_a_marker_guarded_bound_is_evaluated_against_the_venv_interpreter(self):
        # python_version >= "3.12" is true here, so the bound applies and blocks 3.0
        requiring = dist_dir(self.venv, "requirer")
        (requiring / "METADATA").write_text(
            'Metadata-Version: 2.1\nName: requirer\nVersion: 9.0\n'
            'Requires-Dist: other<2; python_version >= "3.12"\n')
        derived = pins.derive(self.venv,
                              [{"name": "tool", "version": "1.0"},
                               {"name": "requirer", "version": "9.0"}],
                              [{"name": "other", "version": "3.0"}],
                              environment=pins.marker_environment({"path": str(self.venv)}))
        self.assertEqual(derived["pins"], [])
        self.assertIn("other", derived["blocked"])

    def test_a_false_marker_lets_the_upgrade_through(self):
        requiring = dist_dir(self.venv, "requirer")
        (requiring / "METADATA").write_text(
            'Metadata-Version: 2.1\nName: requirer\nVersion: 9.0\n'
            'Requires-Dist: other<2; python_version < "3"\n')
        derived = pins.derive(self.venv,
                              [{"name": "tool", "version": "1.0"},
                               {"name": "requirer", "version": "9.0"}],
                              [{"name": "other", "version": "3.0"}],
                              environment=pins.marker_environment({"path": str(self.venv)}))
        self.assertEqual([p["name"] for p in derived["pins"]], ["other"])


class OriginPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.root / "state.db")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def target_for(self, venv):
        self.store.add_target("uvtool", {"name": venv.name, "kind": "uvtool", "host": "local",
                                         "path": os.path.realpath(venv),
                                         "realpath": os.path.realpath(venv)})
        return self.store.target(venv.name)

    def runner(self, name):
        return Base.runner(self, latest="2.0", name=name)

    def test_an_undetermined_origin_makes_the_target_unplannable(self):
        venv = make_venv(self.root, "vcs")
        (dist_dir(venv, "vcs") / "direct_url.json").write_text("{not json")
        with self.assertRaises(Exception) as caught:
            venvflow.preview(self.store, self.target_for(venv), runner=self.runner(venv.name),
                             request=Base.no_network, state_dir=self.root / "state")
        self.assertIn("undetermined origin", str(caught.exception))

    def test_a_vcs_install_is_held_at_its_version(self):
        venv = make_venv(self.root, "vcs")
        (dist_dir(venv, "vcs") / "direct_url.json").write_text(json.dumps(
            {"url": "https://github.com/x/y", "vcs_info": {"vcs": "git"}}))
        with self.assertRaises(Exception) as caught:
            venvflow.preview(self.store, self.target_for(venv), runner=self.runner(venv.name),
                             request=Base.no_network, state_dir=self.root / "state")
        self.assertIn("No upgrade", str(caught.exception))


class RawIndexOptionTests(Base):
    def test_the_install_argv_carries_the_raw_credential(self):
        meta = make_venv(self.root, "tool")
        receipt = ('[tool]\nrequirements = [{ name = "tool" }]\n'
                   'index = "https://user:secret@private.example/simple"\n')
        (meta / "uv-receipt.toml").write_text(receipt)
        result = venvflow.preview(self.store, self.t, runner=self.runner(),
                                  request=self.no_network, state_dir=self.state)
        argv = pins.command(self.t["path"], result["constraints"]["path"], result["pins"],
                            venvflow._index_options(self.t))
        self.assertTrue(any("secret" in token for token in argv),
                        "the raw index URL must reach uv, or the install cannot authenticate")
        # stored forms stay clean
        stored = json.loads(self.store.db.execute("SELECT body FROM plans").fetchone()[0])
        self.assertNotIn("secret", json.dumps(stored))


class LifecyclePathTests(Base):
    def test_two_unreadable_identity_reads_set_identity_mismatch(self):
        (self.venv / "uv-receipt.toml").write_text("not toml = =")
        for _ in range(2):
            with self.assertRaises(Exception):
                venvflow.check(self.store, self.t, runner=self.runner(),
                               request=self.no_network)
        state = self.store.db.execute("SELECT state FROM targets WHERE name='tool'").fetchone()[0]
        self.assertEqual(state, "identity_mismatch")

    def test_recovery_publishes_a_token(self):
        (self.venv / probe.NAME).unlink(missing_ok=True)
        self.store.db.execute("UPDATE targets SET state='unresolved_path' WHERE name='tool'")
        venvflow.check(self.store, self.t, runner=self.runner(), request=self.no_network)
        self.assertEqual(probe.read(self.venv)[0], "usable")

    def test_revival_from_a_non_live_state_returns_the_row_to_service(self):
        self.store.db.execute("UPDATE targets SET state='unresolved_path' WHERE name='tool'")
        self.store.remove_target("tool")
        self.store.add_target("uvtool", {"name": "tool", "kind": "uvtool", "host": "local",
                                         "path": os.path.realpath(self.venv),
                                         "realpath": os.path.realpath(self.venv)})
        row = self.store.db.execute(
            "SELECT state, removed FROM targets WHERE name='tool'").fetchone()
        self.assertEqual(tuple(row), ("live", 0))


class CleanupWithCustomDatabaseTests(unittest.TestCase):
    def test_preview_and_cleanup_agree_on_the_constraints_directory(self):
        root = Path(tempfile.mkdtemp())
        state = root / "custom"
        store = store_module.Store(state / "state.db")
        try:
            venv = make_venv(root, "tool")
            store.add_target("uvtool", {"name": "tool", "kind": "uvtool", "host": "local",
                                        "path": os.path.realpath(venv),
                                        "realpath": os.path.realpath(venv)})
            t = store.target("tool")
            result = venvflow.preview(store, t, runner=Base.runner(self),
                                      request=Base.no_network, state_dir=state)
            path = Path(result["constraints"]["path"])
            self.assertTrue(str(path).startswith(str(state)), path)
            store.db.execute("UPDATE plans SET status='stale'")
            store.cleanup()
            self.assertFalse(path.exists())
        finally:
            store.close()
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class FingerprintEnvironmentTests(unittest.TestCase):
    """The approval must be bound to uv's configuration, not only to its variables."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "state").mkdir()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_uv_config_file_in_the_state_hierarchy_changes_the_fingerprint(self):
        state = self.root / "state"
        before = venvflow.fingerprint(state)
        (state / "uv.toml").write_text("[index]\nurl = 'https://private.example/simple'\n")
        self.assertNotEqual(before, venvflow.fingerprint(state))

    def test_editing_that_file_changes_the_fingerprint_again(self):
        state = self.root / "state"
        config = state / "uv.toml"
        config.write_text("index-url = 'https://one.example/simple'\n")
        first = venvflow.fingerprint(state)
        config.write_text("index-url = 'https://two.example/simple'\n")
        self.assertNotEqual(first, venvflow.fingerprint(state))

    def test_the_local_runner_pins_the_working_directory_to_the_state_dir(self):
        seen = {}

        def fake_run(t, argv, **kw):
            seen["path"] = t.get("path")
            return "[]"

        with mock.patch.object(venvflow.adapters, "run", side_effect=fake_run):
            venvflow.local_runner(["uv", "pip", "list"], cwd="/tmp/some-state")
        self.assertEqual(seen["path"], "/tmp/some-state")


class DefaultStateDirTests(unittest.TestCase):
    """Without an explicit state_dir, artifacts go beside the database cleanup reads."""

    def test_preview_defaults_to_the_databases_directory(self):
        root = Path(tempfile.mkdtemp())
        state = root / "custom"
        store = store_module.Store(state / "state.db")
        try:
            venv = make_venv(root, "tool")
            store.add_target("uvtool", {"name": "tool", "kind": "uvtool", "host": "local",
                                        "path": os.path.realpath(venv),
                                        "realpath": os.path.realpath(venv)})
            result = venvflow.preview(store, store.target("tool"), runner=Base.runner(self),
                                      request=Base.no_network)
            path = Path(result["constraints"]["path"])
            self.assertTrue(str(path).startswith(str(state)), path)
            store.db.execute("UPDATE plans SET status='stale'")
            store.cleanup()
            self.assertFalse(path.exists(), "cleanup must find the file preview wrote")
        finally:
            store.close()
            shutil.rmtree(root, ignore_errors=True)


class ConstraintSourceTests(Base):
    def test_a_bound_from_a_distribution_being_replaced_is_not_written(self):
        """Its bound describes the version being left behind, not the one being installed."""
        requiring = dist_dir(self.venv, "tool")          # the tool is itself the requirer
        (requiring / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: tool\nVersion: 1.0\nRequires-Dist: other<2\n")
        listing = [{"name": "tool", "version": "1.0"}]

        def run(argv, **kw):
            if "--outdated" in argv:
                return json.dumps([{"name": "tool", "version": "1.0", "latest_version": "2.0"}])
            if "check" in argv:
                return "No broken requirements found."
            return json.dumps(listing)

        result = venvflow.preview(self.store, self.t, runner=run,
                                  request=self.no_network, state_dir=self.state)
        body = Path(result["constraints"]["path"]).read_text()
        self.assertIn("tool==2.0", body)
        self.assertNotIn("other<2", body)


class CredentialedIndexApplyTests(Base):
    """A private-index tool must be previewable *and* appliable."""

    def setUp(self):
        super().setUp()
        (self.venv / "uv-receipt.toml").write_text(
            '[tool]\nrequirements = [{ name = "tool" }]\n'
            'index = "https://user:secret@private.example/simple"\n')

    def test_preview_then_apply_with_a_credentialed_index(self):
        installed = {"version": "1.0"}

        def runner(argv, **kw):
            if "install" in argv:
                return seen.setdefault("argv", argv) and ""
            if "--outdated" in argv:
                return json.dumps([{"name": "tool", "version": installed["version"],
                                    "latest_version": "2.0"}])
            if "check" in argv:
                return "No broken requirements found."
            return json.dumps([{"name": "tool", "version": installed["version"]}])

        preview = venvflow.preview(self.store, self.t, runner=runner,
                                   request=self.no_network, state_dir=self.state)
        seen = {}

        def installer(argv, **kw):
            if "install" in argv:
                seen["argv"] = argv
                installed["version"] = "2.0"     # the install actually happened
                return ""
            return runner(argv, **kw)

        result = venvflow.apply(self.store, preview["id"], yes=True, runner=installer,
                                request=self.no_network)
        self.assertEqual(result["status"], "applied", result)
        # the install authenticates with the raw URL, from the verified copy
        self.assertTrue(any("secret" in token for token in seen["argv"]))
        self.assertTrue(seen["argv"][6].endswith(".tmp"), seen["argv"][6])

    def test_pipx_pip_args_keep_their_credential_for_use(self):
        venv = make_venv(self.root, "px", receipt="[tool]\nrequirements = [{ name = \"px\" }]\n")
        meta = json.loads((FIXTURES / "pipx-metadata.json").read_text())
        meta["main_package"]["package"] = "px"
        meta["main_package"]["pip_args"] = ["--index-url",
                                           "https://user:secret@private.example/simple"]
        (venv / "uv-receipt.toml").unlink()
        (venv / "pipx_metadata.json").write_text(json.dumps(meta))
        row = userlane.describe(venv)
        self.assertTrue(any("secret" in token for token in row["index_options"]))
        self.assertFalse(any("secret" in token for token in row["index_options_redacted"]))


class RemoveRefusalTests(Base):
    def test_remove_refuses_while_an_update_is_running(self):
        from netwatch import cli
        self.store.db.execute(
            "INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
            ("tool", int(time.time()), "running", json.dumps({"target": self.t})))
        with self.assertRaises(Exception) as caught:
            cli.dispatch(cli.parser().parse_args(["targets", "remove", "tool"]),
                         self.store, None, None)
        self.assertIn("running", str(caught.exception))
        self.assertEqual(
            self.store.db.execute("SELECT removed FROM targets WHERE name='tool'").fetchone()[0], 0)
