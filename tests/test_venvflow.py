import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from netwatch import probe, store as store_module, venvflow, workflow

FIXTURES = Path(__file__).parent / "fixtures"


def build(root: Path, name="tool"):
    venv = root / "tools" / name
    venv.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("")
    (venv / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    dist = venv / "lib" / "python3.12" / "site-packages" / ("%s-1.0.dist-info" % name)
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: 1.0\n" % name)
    receipt = (FIXTURES / "uv-receipt.toml").read_text().replace('"ruff"', '"%s"' % name)
    (venv / "uv-receipt.toml").write_text(receipt)
    return venv


def runner_for(name, latest="2.0", packages=None):
    listing = json.dumps([{"name": name, "version": "1.0"}])
    outdated = json.dumps([{"name": name, "version": "1.0", "latest_version": latest}])

    def run(argv, **kw):
        if "--outdated" in argv:
            return outdated
        if "list" in argv:
            return listing
        return ""
    return run


class VenvCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        self.venv = build(self.root)
        self.store = store_module.Store(self.state)
        self.store.add_target("uvtool", {"name": "tool", "kind": "uvtool", "host": "local",
                                         "path": str(self.venv)})
        self.t = self.store.target("tool")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def no_network(self, url, body=None):
        return {"vulns": []}

    def state_row(self):
        row = self.store.db.execute("SELECT state, state_seq FROM targets WHERE name='tool'").fetchone()
        return tuple(row)


class CheckTests(VenvCase):
    def test_a_healthy_check_publishes_a_token_and_saves_a_report(self):
        report = venvflow.check(self.store, self.t, runner=runner_for("tool"), request=self.no_network)
        self.assertEqual(probe.read(self.venv)[0], "usable")
        self.assertEqual([p["name"] for p in report["packages"]], ["tool"])
        self.assertTrue(report["advisory_check_ok"])
        self.assertEqual(self.state_row(), ("live", 0))

    def test_a_witness_mismatch_publishes_nothing(self):
        with mock.patch.object(venvflow.probe, "witness",
                               side_effect=[{"kind": "inodes", "value": [1, 1, 1]},
                                            {"kind": "inodes", "value": [2, 2, 2]}]):
            with self.assertRaises(Exception):
                venvflow.check(self.store, self.t, runner=runner_for("tool"),
                               request=self.no_network)
        self.assertIsNone(self.store.latest("tool"))

    def test_a_token_that_vanishes_is_a_mismatch_not_an_inode_fallback(self):
        self.assertTrue(venvflow._witness_equal({"kind": "token", "value": "a"},
                                                {"kind": "inodes", "value": [1, 1, 1]}) is False)

    def test_a_target_with_a_co_claimant_publishes_nothing(self):
        """Two registrations on one venv: neither reports under both names."""
        self.store.add_target("uvtool", {"name": "twin", "kind": "uvtool", "host": "local",
                                         "path": str(self.venv / ".")})
        with self.assertRaises(Exception) as caught:
            venvflow.check(self.store, self.t, runner=runner_for("tool"),
                           request=self.no_network)
        self.assertIn("out of service", str(caught.exception))
        self.assertIsNone(self.store.latest("tool"))

    def test_a_missing_path_sets_nothing_on_the_first_observation(self):
        shutil.rmtree(self.venv)
        with self.assertRaises(Exception):
            venvflow.check(self.store, self.t, runner=runner_for("tool"), request=self.no_network)
        self.assertEqual(self.state_row()[0], "live")

    def test_a_second_missing_path_observation_sets_unresolved_path(self):
        shutil.rmtree(self.venv)
        for _ in range(2):
            with self.assertRaises(Exception):
                venvflow.check(self.store, self.t, runner=runner_for("tool"),
                               request=self.no_network)
        self.assertEqual(self.state_row()[0], "unresolved_path")


class PreviewTests(VenvCase):
    def test_preview_saves_a_plan_with_constraints_token_and_generation(self):
        result = venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                                  request=self.no_network, state_dir=self.root / "state")
        self.assertEqual(result["status"], "proposed")
        self.assertEqual(result["generation"], 1)
        self.assertTrue(Path(result["constraints"]["path"]).is_file())
        self.assertIn("tool==2.0", result["commands"][0])
        self.assertEqual(probe.read(self.venv)[0], "usable")

    def test_a_changing_fingerprint_saves_no_plan(self):
        with mock.patch.object(venvflow, "fingerprint", side_effect=["a", "b"]):
            with self.assertRaises(Exception):
                venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                                 request=self.no_network, state_dir=self.root / "state")
        self.assertIsNone(self.store.db.execute("SELECT id FROM plans").fetchone())

    def test_stable_fingerprints_save_the_plan(self):
        with mock.patch.object(venvflow, "fingerprint", side_effect=["a", "a", "a"]):
            result = venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                                      request=self.no_network, state_dir=self.root / "state")
        self.assertEqual(result["fingerprint"], "a")

    def test_preview_refuses_an_out_of_service_target(self):
        self.store.db.execute("UPDATE targets SET state='unresolved_path' WHERE name='tool'")
        with self.assertRaises(Exception) as caught:
            venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                             request=self.no_network, state_dir=self.root / "state")
        self.assertIn("unresolved_path", str(caught.exception))

    def test_preview_refuses_a_not_bindable_target(self):
        self.store.db.execute("UPDATE targets SET state='not_bindable' WHERE name='tool'")
        with self.assertRaises(Exception) as caught:
            venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                             request=self.no_network, state_dir=self.root / "state")
        self.assertIn("probe token", str(caught.exception))

    def test_preview_refuses_when_no_upgrade_respects_the_bounds(self):
        with self.assertRaises(Exception) as caught:
            venvflow.preview(self.store, self.t, runner=runner_for("tool", latest="1.0"),
                             request=self.no_network, state_dir=self.root / "state")
        self.assertIn("No upgrade", str(caught.exception))


class FingerprintTests(unittest.TestCase):
    def test_the_same_environment_fingerprints_the_same(self):
        first = venvflow.fingerprint()
        self.assertEqual(first, venvflow.fingerprint())

    def test_a_changed_index_variable_changes_the_fingerprint(self):
        import os
        first = venvflow.fingerprint()
        os.environ["UV_INDEX_URL"] = "https://example.invalid/simple"
        try:
            self.assertNotEqual(first, venvflow.fingerprint())
        finally:
            del os.environ["UV_INDEX_URL"]

    def test_a_rotated_credential_does_not_change_the_fingerprint(self):
        import os
        os.environ["UV_INDEX_URL"] = "https://user:one@pypi.example/simple"
        try:
            first = venvflow.fingerprint()
            os.environ["UV_INDEX_URL"] = "https://user:two@pypi.example/simple"
            self.assertEqual(first, venvflow.fingerprint())
        finally:
            del os.environ["UV_INDEX_URL"]


if __name__ == "__main__":
    unittest.main()
