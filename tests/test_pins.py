import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from netwatch import pins


def make_dist(venv: Path, name, version, requires=(), entry_points=None, direct_url=None):
    dist = venv / "lib" / "python3.12" / "site-packages" / ("%s-%s.dist-info" % (name, version))
    dist.mkdir(parents=True, exist_ok=True)
    lines = ["Metadata-Version: 2.1", "Name: %s" % name, "Version: %s" % version]
    lines.extend("Requires-Dist: " + r for r in requires)
    (dist / "METADATA").write_text("\n".join(lines) + "\n")
    if entry_points is not None:
        body = ["[console_scripts]"] + ["%s = %s" % (k, v) for k, v in entry_points.items()]
        (dist / "entry_points.txt").write_text("\n".join(body) + "\n")
    if direct_url is not None:
        (dist / "direct_url.json").write_text(json.dumps(direct_url))
    return dist


def make_venv(root: Path):
    venv = root / "v"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("")
    return venv


class DeriveTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def packages(self, *rows):
        return [{"name": n, "version": v} for n, v in rows]

    def test_a_pin_the_retained_bounds_forbid_is_not_selected(self):
        make_dist(self.venv, "tool", "1.0", requires=["dep<2"])
        result = pins.derive(self.venv, self.packages(("tool", "1.0"), ("dep", "1.0")),
                             [{"name": "dep", "version": "3.0"}], tool="tool")
        self.assertEqual(result["pins"], [])
        self.assertIn("dep", result["excluded"])

    def test_upgrading_a_distribution_retires_its_own_old_bound(self):
        # tool 1.0 requires dep<2; tool 2.0 is the upgrade and no longer bounds dep.
        make_dist(self.venv, "tool", "1.0", requires=["dep<2"])
        result = pins.derive(self.venv, self.packages(("tool", "1.0"), ("dep", "1.0")),
                             [{"name": "tool", "version": "2.0"}, {"name": "dep", "version": "3.0"}],
                             tool="tool")
        self.assertEqual([p["name"] for p in result["pins"]], ["dep", "tool"])

    def test_the_pass_bound_is_the_number_of_installed_distributions_plus_one(self):
        make_dist(self.venv, "a", "1.0", requires=["b<2"])
        make_dist(self.venv, "b", "1.0", requires=["c<2"])
        make_dist(self.venv, "c", "1.0")
        result = pins.derive(self.venv, self.packages(("a", "1.0"), ("b", "1.0"), ("c", "1.0")),
                             [{"name": "b", "version": "3.0"}, {"name": "c", "version": "3.0"}])
        self.assertTrue(all(p["version"] == "3.0" for p in result["pins"]))

    def test_the_tools_own_pin_carries_its_observed_extras(self):
        make_dist(self.venv, "tool", "1.0")
        result = pins.derive(self.venv, self.packages(("tool", "1.0")),
                             [{"name": "tool", "version": "2.0"}], extras=["server"], tool="tool")
        self.assertEqual(result["pins"][0]["extras"], ["server"])
        self.assertEqual(pins.pin_text(result["pins"][0]), "tool[server]==2.0")

    def test_a_dependency_referenced_with_extras_keeps_them(self):
        make_dist(self.venv, "tool", "1.0", requires=["dep[fast]>=1"])
        make_dist(self.venv, "dep", "1.0")
        result = pins.derive(self.venv, self.packages(("tool", "1.0"), ("dep", "1.0")),
                             [{"name": "dep", "version": "2.0"}], tool="tool")
        dep = [p for p in result["pins"] if p["name"] == "dep"][0]
        self.assertEqual(dep["extras"], ["fast"])

    def test_a_reference_guarded_by_an_unknown_extra_is_a_lead(self):
        make_dist(self.venv, "other", "1.0", requires=['dep[cli]; extra == "client"'])
        make_dist(self.venv, "dep", "1.0")
        result = pins.derive(self.venv, self.packages(("other", "1.0"), ("dep", "1.0")),
                             [{"name": "dep", "version": "2.0"}])
        dep = [p for p in result["pins"] if p["name"] == "dep"][0]
        self.assertEqual(dep["extras"], [])
        self.assertEqual(result["leads"][0]["type"], "extras")

    def test_no_candidates_means_no_pins(self):
        make_dist(self.venv, "tool", "1.0")
        result = pins.derive(self.venv, self.packages(("tool", "1.0")), [], tool="tool")
        self.assertEqual(result["pins"], [])


class OriginTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_missing_file_is_index_origin(self):
        dist = make_dist(self.venv, "tool", "1.0")
        self.assertEqual(pins.origin(dist), ("index", {}))

    def test_a_malformed_file_is_undetermined(self):
        dist = make_dist(self.venv, "tool", "1.0")
        (dist / "direct_url.json").write_text("{not json")
        self.assertEqual(pins.origin(dist)[0], "undetermined")

    def test_valid_json_without_provenance_is_undetermined(self):
        dist = make_dist(self.venv, "tool", "1.0", direct_url={})
        self.assertEqual(pins.origin(dist)[0], "undetermined")

    def test_a_vcs_install_is_reported_as_such(self):
        dist = make_dist(self.venv, "tool", "1.0",
                         direct_url={"url": "https://github.com/x/y", "vcs_info": {"vcs": "git"}})
        self.assertEqual(pins.origin(dist)[0], "vcs")

    def test_a_local_install_is_reported_as_such(self):
        dist = make_dist(self.venv, "tool", "1.0", direct_url={"url": "file:///tmp/x", "dir_info": {}})
        self.assertEqual(pins.origin(dist)[0], "local")


class CommandTests(unittest.TestCase):
    def pins(self):
        return [{"name": "ruff", "version": "0.16.0", "extras": []},
                {"name": "click", "version": "8.2.0", "extras": ["color"]}]

    def test_the_argv_names_the_recorded_venv_constraints_and_pins(self):
        argv = pins.command("/v", "/state/constraints/preview-abc.txt", self.pins())
        self.assertEqual(argv[:6], ["uv", "pip", "install", "--python", "/v/bin/python", "-c"])
        self.assertEqual(argv[6], "/state/constraints/preview-abc.txt")
        self.assertIn("ruff==0.16.0", argv)
        self.assertIn("click[color]==8.2.0", argv)

    def test_no_upgrade_and_no_no_config_flag(self):
        argv = pins.command("/v", "/c.txt", self.pins())
        for forbidden in ("--upgrade", "-U", "--no-config", "--upgrade-strategy"):
            self.assertNotIn(forbidden, argv)

    def test_recorded_index_options_are_replayed_before_the_pins(self):
        argv = pins.command("/v", "/c.txt", self.pins(),
                            ["--index-url", "https://pypi.example/simple"])
        self.assertIn("--index-url", argv)
        self.assertLess(argv.index("--index-url"), argv.index("ruff==0.16.0"))

    def test_redaction_strips_credentials_from_recorded_options(self):
        argv = pins.command("/v", "/c.txt", self.pins(),
                            ["--index-url", "https://user:secret@pypi.example/simple"])
        shown = pins.redacted(argv)
        self.assertIn("https://pypi.example/simple", shown)
        self.assertFalse(any("secret" in token for token in shown))

    def test_the_plan_body_carries_a_digest_of_the_exact_argv(self):
        body = pins.plan_body("/v", "/c.txt", self.pins(), target={"name": "ruff"})
        self.assertEqual(body["command_digest"], pins.digest(body["commands"][0]))
        self.assertEqual(body["command_redacted"][:4], body["commands"][0][:4])


if __name__ == "__main__":
    unittest.main()
