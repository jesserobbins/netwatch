import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from netwatch import probe, store as store_module, venvflow, workflow

FIXTURES = Path(__file__).parent / "fixtures"


def write_record(site: Path, dist: Path, name: str):
    """A RECORD with real hashes, so the classifier's integrity pass has something to read."""
    import hashlib
    lines = []
    module = site / ("%s.py" % name)
    module.write_text("VERSION = 'x'\n")
    for path in (module, dist / "METADATA"):
        rel = path.relative_to(site)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append("%s,sha256=%s,%d" % (rel, digest, path.stat().st_size))
    lines.append("%s,," % (dist / "RECORD").relative_to(site))
    (dist / "RECORD").write_text("\n".join(lines) + "\n")


def build(root: Path, name="tool"):
    import sys
    venv = root / "tools" / name
    (venv / "bin").mkdir(parents=True)
    # A real interpreter symlink: preview and apply read its `-I -S` marker values.
    (venv / "bin" / "python").symlink_to(sys.executable)
    (venv / "pyvenv.cfg").write_text("")
    (venv / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    dist = venv / "lib" / "python3.12" / "site-packages" / ("%s-1.0.dist-info" % name)
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: 1.0\n" % name)
    write_record(dist.parent, dist, name)
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
        self.assertIn("tool==2.0", result["commands_redacted"][0])
        self.assertEqual(probe.read(self.venv)[0], "usable")

    def test_a_changing_fingerprint_saves_no_plan(self):
        with mock.patch.object(venvflow, "fingerprint", side_effect=["a", "b", "b", "b"]):
            with self.assertRaises(Exception):
                venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                                 request=self.no_network, state_dir=self.root / "state")
        self.assertIsNone(self.store.db.execute("SELECT id FROM plans").fetchone())

    def test_stable_fingerprints_save_the_plan(self):
        with mock.patch.object(venvflow, "fingerprint", side_effect=["a", "a", "a", "a"]):
            result = venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                                      request=self.no_network, state_dir=self.root / "state")
        self.assertEqual(result["fingerprint"], "a")

    def test_preview_refuses_an_out_of_service_target(self):
        self.store.db.execute("UPDATE targets SET state='unresolved_path' WHERE name='tool'")
        with self.assertRaises(Exception) as caught:
            venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                             request=self.no_network, state_dir=self.root / "state")
        self.assertIn("unresolved_path", str(caught.exception))

    def test_preview_recovers_a_not_bindable_target(self):
        """Recovering the token is what preview is for: it must not gate on not_bindable."""
        self.store.db.execute("UPDATE targets SET state='not_bindable' WHERE name='tool'")
        result = venvflow.preview(self.store, self.t, runner=runner_for("tool"),
                                  request=self.no_network, state_dir=self.root / "state")
        self.assertEqual(result["status"], "proposed")
        self.assertEqual(probe.read(self.venv)[0], "usable")

    def test_no_eligible_update_is_reported_not_raised(self):
        """(p11): no eligible update is an observation; no plan is saved."""
        result = venvflow.preview(self.store, self.t, runner=runner_for("tool", latest="1.0"),
                                  request=self.no_network, state_dir=self.root / "state")
        self.assertEqual(result["status"], "no_update")
        self.assertIn("No eligible update", result["detail"])
        self.assertIsNone(self.store.db.execute("SELECT id FROM plans").fetchone())


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


class ApplyCase(VenvCase):
    def setUp(self):
        super().setUp()
        self.installed = {"tool": "1.0"}
        self.consistency = []
        self.fail_install = None
        self.after_install = None
        plan = venvflow.preview(self.store, self.t, runner=self.runner_fn, request=self.no_network,
                                state_dir=self.root / "state")
        self.plan = plan

    def runner_fn(self, argv, **kw):
        if "--outdated" in argv:
            return json.dumps([{"name": "tool", "version": self.installed["tool"],
                                "latest_version": "2.0"}])
        if "check" in argv:
            return "\n".join(self.consistency) or "No broken requirements found."
        if "install" in argv:
            # The command runs — possibly damaging the venv — and only then may fail.
            if self.after_install:
                self.after_install()
            if self.fail_install:
                raise Exception(self.fail_install)
            self.installed["tool"] = "2.0"
            return ""
        return json.dumps([{"name": n, "version": v} for n, v in self.installed.items()])

    def apply(self, **kw):
        return venvflow.apply(self.store, self.plan["id"], yes=True, runner=self.runner_fn,
                              request=self.no_network, **kw)

    def plan_status(self):
        return self.store.db.execute("SELECT status FROM plans WHERE id=?", (self.plan["id"],)).fetchone()[0]


class ApplyGateTests(ApplyCase):
    def test_a_clean_install_is_applied(self):
        result = self.apply()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(self.plan_status(), "applied")

    def test_apply_requires_yes(self):
        with self.assertRaises(Exception):
            venvflow.apply(self.store, self.plan["id"], yes=False, runner=self.runner_fn)
        self.assertEqual(self.plan_status(), "proposed")

    def test_a_changed_probe_token_is_a_stale_approval(self):
        (self.venv / probe.NAME).write_text("netwatch-probe: 11111111-2222-3333-4444-555555555555\n")
        with self.assertRaises(Exception) as caught:
            self.apply()
        self.assertIn("probe", str(caught.exception))
        self.assertEqual(self.plan_status(), "proposed")

    def test_a_revived_generation_is_a_stale_approval(self):
        self.store.remove_target("tool")
        self.store.add_target("uvtool", {"name": "tool", "kind": "uvtool", "host": "local",
                                         "path": str(self.venv)})
        with self.assertRaises(Exception) as caught:
            self.apply()
        self.assertIn("revived", str(caught.exception))

    def test_a_changed_configuration_is_a_stale_approval(self):
        with mock.patch.object(venvflow, "fingerprint", return_value="different"):
            with self.assertRaises(Exception) as caught:
                self.apply()
        self.assertIn("Configuration changed", str(caught.exception))

    def test_a_changed_inventory_is_a_stale_approval(self):
        self.installed["tool"] = "1.5"
        with self.assertRaises(Exception) as caught:
            self.apply()
        self.assertIn("changed", str(caught.exception))

    def test_a_missing_constraints_file_is_a_stale_approval(self):
        Path(self.plan["constraints"]["path"]).unlink()
        with self.assertRaises(Exception) as caught:
            self.apply()
        self.assertIn("constraints file", str(caught.exception))


class ApplyClassificationTests(ApplyCase):
    def test_a_failure_that_changed_nothing_returns_the_plan_to_proposed(self):
        self.fail_install = "Command failed: uv pip install (exit 1)"
        result = self.apply()
        self.assertEqual(result["status"], "failed_no_change")
        self.assertEqual(self.plan_status(), "proposed")
        self.assertIn("install_output", result)

    def test_a_failure_that_rewrote_a_file_needs_attention(self):
        def damage():
            site = self.venv / "lib" / "python3.12" / "site-packages"
            (site / "tool.py").write_text("VERSION = 'tampered'\n")
        self.after_install = damage
        self.fail_install = "Command failed: uv pip install (exit 1)"
        result = self.apply()
        self.assertEqual(result["status"], "needs_attention")
        self.assertTrue(result["record_mismatches"])
        self.assertEqual(self.plan_status(), "needs_attention")

    def test_a_new_consistency_entry_after_the_install_needs_attention(self):
        def worse():
            self.consistency = ["tool 2.0 requires dep>=3 which is not installed"]
        self.after_install = worse
        result = self.apply()
        self.assertEqual(result["status"], "needs_attention")
        self.assertIn("consistency", " ".join(result["problems"]))

    def test_a_changed_origin_after_the_install_needs_attention(self):
        def swap():
            site = self.venv / "lib" / "python3.12" / "site-packages"
            dist = next(site.glob("tool-*.dist-info"))
            (dist / "direct_url.json").write_text(json.dumps(
                {"url": "https://example.invalid/x", "vcs_info": {"vcs": "git"}}))
        self.after_install = swap
        result = self.apply()
        self.assertEqual(result["status"], "needs_attention")
        self.assertIn("origin", " ".join(result["problems"]))

    def test_a_terminal_write_stales_sibling_plans_for_the_same_venv(self):
        sibling = self.store.db.execute(
            "INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
            ("tool", int(time.time()), "proposed",
             json.dumps({"target": self.t, "commands": [["true"]],
                         "expires_at": int(time.time()) + 3600}))).lastrowid
        self.apply()
        status = self.store.db.execute("SELECT status FROM plans WHERE id=?", (sibling,)).fetchone()[0]
        self.assertEqual(status, "stale")


class CheckShowsDriftTests(VenvCase):
    """The headline complaint: check must show that an upgrade exists."""

    def test_check_reports_available_updates(self):
        report = venvflow.check(self.store, self.t, runner=runner_for("tool"),
                                request=self.no_network)
        self.assertEqual([u["package"] for u in report["updates"]], ["tool"])
        self.assertEqual(report["updates"][0]["candidate"], "2.0")

    def test_check_records_an_update_error_instead_of_pretending_there_is_none(self):
        def broken(argv, **kw):
            if "--outdated" in argv:
                raise venvflow.Error("Command failed: uv pip list --outdated (exit 1)")
            return json.dumps([{"name": "tool", "version": "1.0"}])
        report = venvflow.check(self.store, self.t, runner=broken, request=self.no_network)
        self.assertEqual(report["updates"], [])
        self.assertIn("outdated", (report["update_error"] or "").lower())

    def test_check_reports_a_broken_launcher(self):
        import sys
        site = self.venv / "lib" / "python3.12" / "site-packages"
        dist = next(site.glob("tool-*.dist-info"))
        (dist / "entry_points.txt").write_text("[console_scripts]\ntool = tool.cli:main\n")
        script = self.venv / "bin" / "tool"
        (self.venv / "uv-receipt.toml").write_text(
            '[tool]\nrequirements = [{ name = "tool" }]\nentrypoints = [\n'
            '  { name = "tool", install-path = "%s", from = "tool" },\n]\n' % script)
        script.write_text("#!/bin/sh\n'''exec' /usr/bin/python3 \"$0\" \"$@\"\n' '''\n")
        report = venvflow.check(self.store, self.t, runner=runner_for("tool"),
                                request=self.no_network)
        reasons = [f["reason"] for f in report["findings"] if f["advisory"].startswith("launcher")]
        self.assertTrue(reasons, report["findings"])
        self.assertIn("outside", reasons[0])


class StructuralDriftTests(VenvCase):
    def test_a_path_component_that_turned_symlink_is_caught(self):
        real = self.root / "elsewhere"
        real.mkdir()
        (real / "pyvenv.cfg").write_text("")
        self.store.add_target("uvtool", {"name": "drifted", "kind": "uvtool", "host": "local",
                                         "path": str(self.venv), "realpath": str(self.venv)})
        drifted = self.root / "alias"
        os.symlink(real, drifted)
        target = self.store.target("drifted")
        target["path"] = str(drifted)
        self.store.db.execute("UPDATE targets SET body=? WHERE name='drifted'",
                              (json.dumps(target),))
        with self.assertRaises(Exception) as caught:
            venvflow.check(self.store, self.store.target("drifted"),
                           runner=runner_for("drifted"), request=self.no_network)
        self.assertIn("resolves to", str(caught.exception))


class PreExistingDamageTests(ApplyCase):
    def test_a_pre_existing_record_mismatch_does_not_block_a_retry(self):
        site = self.venv / "lib" / "python3.12" / "site-packages"
        (site / "tool.py").write_text("VERSION = 'patched-by-hand'\n")
        self.fail_install = "Command failed: uv pip install (exit 1)"
        result = self.apply()
        self.assertEqual(result["status"], "failed_no_change", result)
        self.assertEqual(self.plan_status(), "proposed")


class InventoryDigestTests(VenvCase):
    """A same-version reinstall with different metadata is not the approved state."""

    def test_a_metadata_change_at_the_same_version_changes_the_digest(self):
        packages = [{"name": "tool", "version": "1.0"}]
        before = venvflow.inventory_digest(self.t["path"], packages)
        site = self.venv / "lib" / "python3.12" / "site-packages"
        dist = next(site.glob("tool-*.dist-info"))
        (dist / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: tool\nVersion: 1.0\nRequires-Dist: other>=2\n")
        self.assertNotEqual(before, venvflow.inventory_digest(self.t["path"], packages))

    def test_an_origin_appearing_at_the_same_version_changes_the_digest(self):
        packages = [{"name": "tool", "version": "1.0"}]
        before = venvflow.inventory_digest(self.t["path"], packages)
        site = self.venv / "lib" / "python3.12" / "site-packages"
        dist = next(site.glob("tool-*.dist-info"))
        (dist / "direct_url.json").write_text(json.dumps(
            {"url": "https://example.invalid/x", "vcs_info": {"vcs": "git"}}))
        self.assertNotEqual(before, venvflow.inventory_digest(self.t["path"], packages))
