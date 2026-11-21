import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netwatch import adapters, cli, sources, workflow
from netwatch.cli import main
from netwatch.core import Error, canonical
from netwatch.demo import DemoRunner, NOTICE, demo
from netwatch.store import Store


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.db"
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.t = adapters.target("host", "ubuntu")
        self.store.db.execute("INSERT INTO targets VALUES(?,?)", ("host", canonical(self.t)))
        self.runner = DemoRunner()
        self.request = lambda url, body=None: copy.deepcopy(NOTICE)

    def check(self, **kwargs):
        return workflow.check(self.store, self.t, runner=self.runner, request=self.request, **kwargs)

    def test_demo(self):
        self.assertEqual(demo()["result"]["status"], "applied")

    def test_success_approval_replay_and_history(self):
        self.check()
        p = workflow.preview(self.store, self.t, self.runner)
        with self.assertRaises(Error):
            workflow.apply(self.store, p["id"], runner=self.runner)
        result = workflow.apply(self.store, p["id"], yes=True, runner=self.runner, request=self.request)
        self.assertTrue(result["package_state_changed"])
        self.assertFalse(result["remaining_findings"])
        self.assertIn("Not verified", result["runtime"])
        with self.assertRaises(Error):
            workflow.apply(self.store, p["id"], yes=True, runner=self.runner)
        kinds = [e["kind"] for e in self.store.events()]
        self.assertIn("approved_and_started", kinds)
        self.assertIn("finding_no_longer_detected", kinds)
        self.assertEqual(kinds[-1], "applied")

    def test_no_duplicate_changes_on_unchanged_scan(self):
        self.check()
        cursor = self.store.events()[-1]["id"]
        self.check()
        self.assertEqual([e["kind"] for e in self.store.events(cursor)], ["checked"])

    def test_refresh_records_evidence_and_failed_refresh_retains_it(self):
        first = self.check()
        self.assertTrue(first["evidence"][0]["fetched_at"])
        self.assertTrue(first["findings"][0]["first_seen"])
        calls = []
        request = lambda *a: calls.append(a) or copy.deepcopy(NOTICE)
        workflow.check(self.store, self.t, runner=self.runner, request=request)
        self.assertFalse(calls)
        workflow.check(self.store, self.t, runner=self.runner, request=request, refresh=True)
        self.assertEqual(len(calls), 1)
        self.request = lambda *a: (_ for _ in ()).throw(Error("source unavailable"))
        report = self.check(refresh=True)
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertFalse(report["advisory_check_ok"])

    def test_every_adapter_uses_only_approved_commands_and_rechecks(self):
        for kind in adapters.KINDS:
            with self.subTest(kind=kind):
                t = adapters.target(kind, kind, path="/env" if kind in ("uv", "npm", "conda", "mamba") else None)
                self.store.db.execute("INSERT INTO targets VALUES(?,?)", (kind, canonical(t)))
                calls = []
                runner = lambda t, argv, **kw: calls.append(argv) or "no\n"
                packages = [adapters.package("test", "1", "Conda")]
                with patch("netwatch.adapters.inventory", return_value=packages), \
                     patch("netwatch.adapters.updates", return_value=[]), \
                     patch("netwatch.sources.assess", return_value=([], [], True, [])):
                    p = workflow.preview(self.store, t, runner)
                    result = workflow.apply(self.store, p["id"], yes=True, runner=runner)
                self.assertEqual(calls[:len(adapters.commands(t))], adapters.commands(t))
                self.assertEqual(result["status"], "applied")
                self.assertFalse(result["package_state_changed"])

    def test_bad_target_does_not_prevent_other_checks(self):
        bad = adapters.target("offline", "ubuntu")
        self.store.db.execute("INSERT INTO targets VALUES(?,?)", ("offline", canonical(bad)))
        def runner(t, *args, **kwargs):
            if t["name"] == "offline":
                raise Error("unavailable")
            return self.runner(t, *args, **kwargs)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--db", str(self.path), "--json", "check"], runner=runner, request=self.request)
        rows = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]["report"])
        self.assertIn("error", rows[1])
        self.assertEqual(rows[1]["last_attempt"]["kind"], "collection_failed")

    def test_stale_cache_failure_preserves_finding(self):
        self.check()
        self.store.db.execute("UPDATE cache SET at=0")
        report = self.check(offline=True)
        self.assertFalse(report["advisory_check_ok"])
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertFalse(any(e["kind"] == "finding_no_longer_detected" for e in self.store.events()))

    def test_inventory_failure_retains_previous_scan(self):
        previous = self.check()
        with self.assertRaises(Error):
            workflow.check(self.store, self.t, runner=lambda *a, **k: (_ for _ in ()).throw(Error("offline")))
        self.assertEqual(self.store.latest("host")["id"], previous["id"])
        self.assertEqual(self.store.events()[-1]["kind"], "collection_failed")

    def test_changes_and_expiry_deny_apply(self):
        p = workflow.preview(self.store, self.t, self.runner)
        self.runner.version = "1.1-1"
        with self.assertRaisesRegex(Error, "changed"):
            workflow.apply(self.store, p["id"], yes=True, runner=self.runner)
        self.runner.version = "1.0-1"
        with patch("netwatch.workflow.time.time", return_value=p["expires_at"]):
            with self.assertRaisesRegex(Error, "expired"):
                workflow.apply(self.store, p["id"], yes=True, runner=self.runner)

    def test_failure_blocks_new_attempt_until_operator_resolution(self):
        p = workflow.preview(self.store, self.t, self.runner)
        self.runner.fail = True
        with self.assertRaises(Error):
            workflow.apply(self.store, p["id"], yes=True, runner=self.runner)
        q = workflow.preview(self.store, self.t, self.runner)
        with self.assertRaisesRegex(Error, "attention"):
            workflow.apply(self.store, q["id"], yes=True, runner=self.runner)
        self.assertEqual(workflow.resolve(self.store, p["id"], "Inspected stopped process and repaired environment")["status"], "resolved")
        self.runner.fail = False
        with self.assertRaises(Error):
            workflow.apply(self.store, q["id"], yes=True, runner=self.runner)
        fresh = workflow.preview(self.store, self.t, self.runner)
        self.assertEqual(workflow.apply(self.store, fresh["id"], yes=True, runner=self.runner, request=self.request)["status"], "applied")

    def test_cli_queries_and_failure_exit(self):
        def cli(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["--db", str(self.path), "--json", *args], runner=self.runner, request=self.request)
            return code, json.loads(out.getvalue())
        self.assertEqual(cli("check", "host")[0], 0)
        self.assertEqual(cli("status", "host")[1][0]["report"]["findings"][0]["state"], "affected")
        self.assertGreater(cli("history")[1]["next_cursor"], 0)
        plan = cli("preview", "host")[1]
        self.assertEqual(cli("status", "host")[1][0]["pending_updates"][0]["id"], plan["id"])
        self.assertEqual(cli("add", "host", "ubuntu")[0], 1)
        self.assertEqual(cli("add", "app", "uv", "--path", "/srv/app")[0], 0)
        self.assertEqual(len(cli("list")[1]), 2)

    def test_store_old_schema_private_permissions_and_cache(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        count = []
        loader = lambda: count.append(1) or {"ok": True}
        self.assertEqual(self.store.cached("test", loader), {"ok": True})
        self.store.cached("test", loader)
        self.assertEqual(len(count), 1)
        self.store.db.execute("PRAGMA user_version=4")
        with self.assertRaisesRegex(Error, "Incompatible"):
            Store(self.path)


class AdapterTests(unittest.TestCase):
    def runner(self, outputs):
        def run(t, argv, **kwargs):
            self.calls.append((argv, kwargs))
            if not outputs:
                raise AssertionError(argv)
            return outputs.pop(0)
        self.calls = []
        return run

    def test_registry_and_paths(self):
        for kind in adapters.KINDS:
            t = adapters.target("test", kind, path="/srv/env" if kind in ("conda", "mamba", "uv", "npm") else None)
            self.assertTrue(adapters.commands(t))
        for host in ("-oProxyCommand=evil", "a;id", "a\nb"):
            with self.assertRaises(Error):
                adapters.target("x", "ubuntu", host)
        with self.assertRaises(Error):
            adapters.target("x", "uv", path="relative")

    def test_conda_and_mamba_do_not_guess_pypi(self):
        for kind in ("conda", "mamba"):
            t = adapters.target("env", kind, path="/env")
            run = self.runner([json.dumps([{"name": "openssl", "version": "3", "channel": "conda-forge"},
                                          {"name": "requests", "version": "2", "channel": "pypi"}]),
                               '{"success":true,"actions":{"LINK":[{"name":"openssl","version":"4"}]}}'])
            rows = adapters.inventory(t, run)
            self.assertEqual([p["ecosystem"] for p in rows], ["Conda", "PyPI"])
            self.assertEqual(adapters.updates(t, run)[0]["candidate"], "4")
            self.assertEqual(adapters.commands(t)[0], [kind, "update", "--all", "--yes", "--prefix", "/env"])

    def test_uv(self):
        t = adapters.target("uv", "uv", path="/project")
        run = self.runner(['[{"name":"jinja2","version":"2.11.2"}]',
                           '[{"name":"jinja2","version":"2.11.2","latest_version":"3.1.6"}]'])
        self.assertEqual(adapters.inventory(t, run)[0]["ecosystem"], "PyPI")
        self.assertEqual(adapters.updates(t, run)[0]["candidate"], "3.1.6")
        self.assertIn("/project/.venv/bin/python", self.calls[0][0])
        self.assertEqual(adapters.commands(t), [["uv", "lock", "--upgrade"], ["uv", "sync", "--locked"]])

    def test_npm_transitive_multiple_versions(self):
        t = adapters.target("npm", "npm", path="/app")
        run = self.runner(['{"dependencies":{"a":{"version":"1","dependencies":{"a":{"version":"2"}}}}}',
                           '{"a":{"wanted":"3","latest":"4"}}'])
        self.assertEqual(len(adapters.inventory(t, run)), 2)
        self.assertEqual(adapters.updates(t, run)[0]["candidate"], "3")
        self.assertEqual(adapters.commands(t), [["npm", "update", "--ignore-scripts"]])
        with self.assertRaises(Error):
            adapters.inventory(t, self.runner(['{"dependencies":{"a":{"missing":true}}}']))

    def test_arch_cachyos_full_upgrade(self):
        for kind in ("arch", "cachyos"):
            t = adapters.target("os", kind)
            run = self.runner([f'ID={kind}\n', 'custom 1-1\n', 'linux 1-1\ncustom 1-1\n', 'linux 1-1 -> 2-1\n'])
            rows = adapters.inventory(t, run)
            self.assertTrue(next(p for p in rows if p["name"] == "custom")["foreign"])
            self.assertEqual(adapters.updates(t, run)[0]["candidate"], "2-1")
            self.assertEqual(adapters.commands(t), [["sudo", "-n", "pacman", "-Syu", "--noconfirm"]])
            self.assertEqual(self.calls[-1][0], ["checkupdates"])

    def test_ssh_quoting_and_fixed_host(self):
        t = adapters.target("app", "npm", "user@host", "/srv/a';touch bad;'")
        with patch("netwatch.adapters.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b'{}', b'')
            popen.return_value.returncode = 0
            adapters.run(t, ["npm", "ls", "--all", "--json"])
            argv = popen.call_args.args[0]
            import shlex
            self.assertIn(shlex.quote(t["path"]), argv[-1])
            self.assertEqual(argv[-2], "user@host")
            self.assertNotIn("shell", popen.call_args.kwargs)

    def test_brew_target_and_darwin_probe(self):
        t = adapters.target("laptop", "brew")
        self.assertIsNone(t["path"])
        with self.assertRaises(Error):
            adapters.target("laptop", "brew", path="/opt/thing")
        run = self.runner(["Darwin\n", "arm64\n", "15.3.1\n", "501\n"])
        self.assertEqual(adapters.os_info(t, run),
                         {"ID": "macos", "PLATFORM": "arm64", "VERSION": "15.3.1", "UID": "501"})
        self.assertEqual(self.calls[0][0], ["uname", "-s"])

    def test_step_label_names_the_tool_behind_wrappers(self):
        self.assertEqual(adapters.step_label(adapters.brew_env("brew", "upgrade", "--cask")),
                         "brew upgrade --cask")
        self.assertEqual(adapters.step_label(adapters.brew_env("brew", "upgrade", "--formula", cleanup=False)),
                         "brew upgrade --formula")
        argv = adapters.brew_env("brew", "upgrade", "--formula", cleanup=False)
        self.assertEqual(argv[:3], ["env", "-u", "HOMEBREW_NO_INSTALL_CLEANUP"])
        self.assertNotIn("HOMEBREW_NO_INSTALL_CLEANUP=1", argv)  # -u must not be undone
        self.assertIn("NONINTERACTIVE=1", argv)
        self.assertNotEqual(adapters.step_label(["sudo", "-n", "apt-get", "update"]),
                            adapters.step_label(["sudo", "-n", "apt-get", "upgrade", "-y"]))
        remote = ["ssh", "-o", "BatchMode=yes", "host", "cd -- /srv/a && uv lock --upgrade"]
        self.assertEqual(adapters.step_label(remote), "uv lock --upgrade")
        self.assertEqual(adapters.step_label(["ssh", "host", "npm update --ignore-scripts"]),
                         "npm update --ignore-scripts")

    def test_brew_refuses_non_darwin_host(self):
        t = adapters.target("server", "brew")
        with self.assertRaises(Error):
            adapters.os_info(t, self.runner(["Linux\n"]))

    def test_brew_inventory_formulae_and_casks(self):
        t = adapters.target("laptop", "brew")
        formulae = json.dumps({"formulae": [
            {"name": "abseil", "full_name": "abseil", "installed": [{"version": "20260817.0"}]},
            {"name": "python@3.12", "full_name": "python@3.12", "installed": [{"version": "3.12.7"}]},
            {"name": "python@3.13", "full_name": "python@3.13", "installed": [{"version": "3.13.1"}]}]})
        run = self.runner(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", formulae,
                           "abseil 20260817.0\npython@3.12 3.12.7\npython@3.13 3.13.1\n",
                           "claude-code 2.1.311\nantigravity-cli 1.5.13,5999302598852608\n"])
        rows = adapters.inventory(t, run)
        self.assertEqual([(p["name"], p["version"]) for p in rows],
                         [("abseil", "20260817.0"), ("antigravity-cli", "1.5.13,5999302598852608"),
                          ("claude-code", "2.1.311"), ("python@3.12", "3.12.7"), ("python@3.13", "3.13.1")])
        self.assertEqual({p["ecosystem"] for p in rows if p["name"].startswith("python")}, {"Homebrew"})
        self.assertEqual(next(p for p in rows if p["name"] == "claude-code")["ecosystem"], "Homebrew-cask")
        self.assertEqual(self.calls[4][0][-3:], ["info", "--installed", "--json=v2"])
        self.assertEqual(self.calls[6][0][-4:], ["brew", "list", "--cask", "--versions"])
        self.assertEqual(next(p for p in rows if p["name"] == "python@3.12")["tap"], "python@3.12")

    def test_brew_inventory_rejects_unparsable_line(self):
        t = adapters.target("laptop", "brew")
        run = self.runner(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "not json\n"])
        with self.assertRaises(Error):
            adapters.inventory(t, run)

    def test_brew_argv_carries_fixed_path(self):
        t = adapters.target("laptop", "brew")
        argv = adapters.brew_env("brew", "list", "--versions")
        self.assertEqual(argv[0], "env")
        self.assertIn("PATH=" + adapters.MAC_PATH, argv)
        self.assertIn("NONINTERACTIVE=1", argv)
        self.assertEqual(argv[-3:], ["brew", "list", "--versions"])
        self.assertNotIn("sudo", " ".join(" ".join(argv) for argv in adapters.commands(t)))
        # The exact step list is pinned by test_brew_commands_refresh_then_upgrade_by_half.


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.p = {"name": "example", "version": "1.0-1", "ecosystem": "Ubuntu", "source": "example",
                  "source_version": "1.0-1", "architecture": "amd64"}

    def test_ubuntu_wrong_release_pocket_hidden_and_backport(self):
        self.assertEqual(sources.ubuntu([self.p], NOTICE)[0]["state"], "affected")
        p = {**self.p, "source_version": "1.1-1"}
        self.assertEqual(sources.ubuntu([p], NOTICE), [])
        for field, value in (("pocket", "esm-apps"), ("source", "other")):
            data = copy.deepcopy(NOTICE)
            data["10001-1"]["releases"]["noble"]["allbinaries"]["example"][field] = value
            self.assertEqual(sources.ubuntu([self.p], data)[0]["state"], "unknown")
        data = copy.deepcopy(NOTICE)
        data["10001-1"]["is_hidden"] = True
        self.assertEqual(sources.ubuntu([self.p], data)[0]["state"], "unknown")
        data["10001-1"]["releases"]["jammy"] = data["10001-1"]["releases"].pop("noble")
        self.assertEqual(sources.ubuntu([self.p], data), [])

    def test_arch_and_rebuild_uncertainty(self):
        rows = [{"name":"AVG-1", "packages":["test"], "affected":"1-1", "fixed":"2-1", "status":"Fixed"}]
        p = adapters.package("test", "1-1", "Arch", foreign=False)
        compare = lambda pairs: {pair: 0 if pair[0] == pair[1] else -1 for pair in pairs}
        self.assertEqual(sources.arch([p], rows, "arch", compare=compare)[0]["state"], "affected")
        self.assertEqual(sources.arch([p], rows, "cachyos", compare=compare)[0]["state"], "unknown")
        self.assertEqual(sources.arch([{**p,"version":"2-1"}], rows, "arch", compare=compare), [])
        rows[0]["status"] = "Unknown"
        self.assertEqual(sources.arch([p], rows, "arch", compare=compare)[0]["state"], "unknown")

    def test_osv_fixes_only_for_correct_package(self):
        p = adapters.package("jinja2", "2.11.2", "PyPI")
        data = {"vulns":[{"id":"TEST-1", "affected":[
            {"package":{"name":"other","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"9"}]}]},
            {"package":{"name":"jinja2","ecosystem":"PyPI"},"ranges":[{"events":[{"fixed":"2.11.3"}]}]}]}]}
        row = sources.osv(p, data)[0]
        self.assertEqual(row["fix_versions"], ["2.11.3"])
        self.assertEqual(row["state"], "affected")
        data["vulns"][0]["withdrawn"] = "2020"
        self.assertEqual(sources.osv(p, data), [])

    def test_bad_sources_do_not_turn_into_clean_reports(self):
        for parse, data in ((sources.ubuntu, {}), (sources.arch, [])):
            with self.assertRaises(Error):
                parse([], data, "arch") if parse == sources.arch else parse([], data)
        with self.assertRaises(Error):
            sources.osv(adapters.package("p", "1", "PyPI"), {"error": "bad request"})
        compact = sources.compact_usn({**NOTICE, "999-1": {"id": "999-1", "releases": {}}})
        self.assertEqual(set(compact), {"10001-1"})

    def test_conda_coverage_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            db = Store(Path(root)/"db")
            try:
                t = adapters.target("env", "conda", path="/env")
                rows, warnings, ok, evidence = sources.assess(t, [adapters.package("openssl", "3", "Conda")], db,
                                                  request=lambda *a: self.fail("must not guess PyPI"))
                self.assertTrue(ok)
                self.assertFalse(rows)
                self.assertTrue(any("unknown" in w for w in warnings))
            finally:
                db.close()


EMPTY_OUTDATED = json.dumps({"formulae": [], "casks": []})

SCAN_PARTIAL = json.dumps({
    "findings": [{"formula": "libheif", "version": "1.23.7", "tag": "v1.23.7",
                  "repo_url": "https://github.com/strukturag/libheif",
                  "vulnerabilities": [{"id": "OSV-2020-2308", "severity": "MEDIUM",
                                       "summary": "Heap-buffer-overflow", "aliases": [],
                                       "fixed_versions": []}]}],
    "skipped_formulae": ["playwright-cli", "lame"], "checked": 1, "complete": False,
    "outdated_without_sbom": [], "unscanned_formulae": {"wacli": "untrusted_tap"}})



class BrewWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.addCleanup(self.store.close)
        self.t = adapters.target("laptop", "brew")
        self.store.db.execute("INSERT INTO targets VALUES(?,?)", ("laptop", canonical(self.t)))

    def scripted(self, outputs, calls=None, formulae="", after=None, taps=None, unloadable=()):
        outputs = list(outputs)
        self.calls = [] if calls is None else calls
        taps = dict(taps or {})
        # `brew info --installed` is synthesized from the installed formulae the fixture
        # describes; once the scan has run, the reconciliation sees the `after` state.
        state = {"scanned": False, "initial": self.info_map(formulae)}
        self.info_after = self.info_map(formulae if after is None else after)
        self.unloadable = list(getattr(self, "unloadable", []))
        def run(t, argv, **kwargs):
            self.calls.append((argv, kwargs))
            if "--installed" in argv:
                source = self.info_after if state["scanned"] else state["initial"]
                return json.dumps({"formulae": [{"name": name, "full_name": taps.get(name, full),
                                                 "installed": [{"version": v} for v in versions]}
                                                for name, (full, versions) in sorted(source.items())]})
            if "list" in argv and "--formula" in argv and "--versions" in argv:
                source = self.info_after if state["scanned"] else state["initial"]
                lines = [f"{name} {' '.join(versions)}\n" for name, (full, versions) in sorted(source.items())]
                lines += [f"{name} 1.0\n" for name in self.unloadable]
                return "".join(lines)
            if not outputs:
                raise AssertionError("Unexpected command: " + json.dumps(argv))
            value = outputs.pop(0)
            if "vulns" in argv and "--json" in argv:
                state["scanned"] = True
            return value
        return run

    @staticmethod
    def info_map(formulae):
        """`name version` lines -> {name: (full_name, [versions])}, kegs merged per name."""
        result = {}
        for line in formulae.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                full, versions = result.get(parts[0], (parts[0], []))
                result[parts[0]] = (full, versions + parts[1:])
        return result

    def scan(self, findings, skipped=(), unscanned=None, complete=False, checked=1):
        return json.dumps({"findings": findings, "skipped_formulae": list(skipped), "checked": checked,
                           "complete": complete, "outdated_without_sbom": [],
                           "unscanned_formulae": unscanned or {}})

    def finding(self, formula, version, advisory="OSV-2020-2308"):
        return {"formula": formula, "version": version, "tag": "v" + version,
                "repo_url": "https://github.com/example/" + formula,
                "vulnerabilities": [{"id": advisory, "severity": "MEDIUM", "summary": "s",
                                     "aliases": [], "fixed_versions": ["9.9"]}]}

    def check(self, formulae, scan_json, *, after="same", taps=None, unloadable=()):
        """Run a check. `after` is the inventory seen when the scan's own re-collection runs:
        "same" (the host held still), None (no re-collection), or an explicit inventory."""
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan_json,
                   "Darwin\n", "arm64\n", "15.3.1\n", "501\n"]
        outputs += [EMPTY_OUTDATED, EMPTY_OUTDATED]  # brew outdated, then --greedy
        self.unloadable = list(unloadable)
        runner = self.scripted(outputs, formulae=formulae,
                               after=formulae if after == "same" else after, taps=taps)
        return workflow.check(self.store, self.t, runner=runner,
                              request=lambda url, body=None: {})

    INSTALLED = "libheif 1.23.7\nlame 3.100\n"

    def test_coverage_is_on_the_report_and_partial_scan_is_not_a_failure(self):
        report = self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")], skipped=["lame"]))
        self.assertTrue(report["advisory_check_ok"])
        self.assertFalse(report["coverage"]["complete"])
        self.assertEqual(report["coverage"]["scanned"], ["libheif"])
        self.assertEqual(report["coverage"]["retained"], ["lame"])
        self.assertTrue(any("absence of findings" in w for w in report["warnings"]))

    def test_scanned_formula_clears_after_upgrade_despite_partial_coverage(self):
        self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")], skipped=["lame"]))
        report = self.check("libheif 1.24.0\nlame 3.100\n", self.scan([], skipped=["lame"]))
        self.assertEqual(report["findings"], [])
        self.assertIn("finding_no_longer_detected", [e["kind"] for e in self.store.events()])

    def test_skipped_formula_upgrade_retires_the_old_version_finding(self):
        # A finding for a skipped formula is contradictory, so seed while lame is covered
        # (checked accounts for both formulae), then upgrade lame while Homebrew skips it.
        self.check(self.INSTALLED, self.scan([self.finding("lame", "3.100", "OSV-1")],
                                            complete=True, checked=2))
        report = self.check("libheif 1.23.7\nlame 3.101\n", self.scan([], skipped=["lame"]))
        self.assertEqual(report["findings"], [])
        self.assertIn("finding_no_longer_detected", [e["kind"] for e in self.store.events()])

    def test_version_change_between_collection_and_scan_keeps_prior_finding(self):
        self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")], complete=True, checked=2))
        report = self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.24.0")], complete=True, checked=2))
        self.assertEqual([f["advisory"] for f in report["findings"]], ["OSV-2020-2308"])
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertTrue(any("changed version" in w for w in report["warnings"]))

    def test_inventory_change_during_the_scan_retains_prior_findings(self):
        self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")], complete=True, checked=2))
        report = self.check(self.INSTALLED, self.scan([], complete=True, checked=2),
                            after="libheif 1.24.0\nlame 3.100\n")
        self.assertNotIn("unaccounted", report["coverage"])
        self.assertFalse(report["advisory_check_ok"])
        self.assertEqual([f["advisory"] for f in report["findings"]], ["OSV-2020-2308"])
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertTrue(report["coverage"]["changed_during_scan"])
        self.assertTrue(any("did not hold still" in w or "changed or could not be re-read" in w
                            for w in report["warnings"]))

    def test_outdated_without_sbom_findings_are_not_published(self):
        report = self.check(self.INSTALLED, json.dumps({
            "findings": [self.finding("lame", "3.099")], "skipped_formulae": [], "checked": 2,
            "complete": False, "outdated_without_sbom": ["lame"], "unscanned_formulae": {}}))
        self.assertEqual(report["coverage"]["retained"], ["lame"])
        self.assertEqual(report["coverage"]["scanned"], ["libheif"])
        self.assertEqual(report["findings"], [])
        self.assertTrue(any("current formula version" in w for w in report["warnings"]))
        self.assertFalse(any("changed version" in w for w in report["warnings"]))

    def test_context_trim_drops_rows_whose_subject_cleared(self):
        # A finding citing CVE-1 is cleared between the context fetch and the save; the
        # fresh cve_now and zero_wire rows for it must not ship, a pwn.watch lead matched
        # by a GHSA id must not ship, and a tag-matched pwn.watch lead stays.
        findings = [{"advisory": "GHSA-abcd-efgh-2345", "package": "x", "installed": "1",
                     "references": ["GHSA-abcd-efgh-2345"]}]
        report = {"findings": [],
                  "context": {"cve_now": {"status": "ok", "items": [{"id": "CVE-1"}], "errors": []},
                              "zero_wire": {"status": "ok", "items": [{"references": ["CVE-1"]}], "errors": []},
                              "pwn_watch": {"status": "ok", "items": [
                                  {"references": ["GHSA-abcd-efgh-2345"], "matched_tags": []},
                                  {"references": ["CVE-1"], "matched_tags": ["x"]}], "errors": []}}}
        self.store.save_scan(self.t["name"], dict(report, target=self.t, packages=[], updates=[],
                                                 warnings=[], advisory_check_ok=True, evidence=[],
                                                 matcher_revision=1, update_error=None))
        saved = self.store.latest(self.t["name"])
        self.assertEqual(saved["context"]["cve_now"]["items"], [])
        self.assertEqual(saved["context"]["zero_wire"]["items"], [])
        # The GHSA-matched lead (no tags) goes; the tag-matched lead stays, with its
        # matched_references recomputed against the surviving findings.
        self.assertEqual([i["matched_tags"] for i in saved["context"]["pwn_watch"]["items"]], [["x"]])

    def test_retained_context_survives_the_trim(self):
        report = {"findings": [],
                  "context": {"cve_now": {"status": "incomplete", "items": [{"id": "CVE-1", "retained": True}],
                                          "errors": ["down"]}}}
        self.store.save_scan(self.t["name"], dict(report, target=self.t, packages=[], updates=[],
                                                  warnings=[], advisory_check_ok=True, evidence=[],
                                                  matcher_revision=1, update_error=None))
        saved = self.store.latest(self.t["name"])
        self.assertEqual(saved["context"]["cve_now"]["items"], [{"id": "CVE-1", "retained": True}])

    def test_failed_step_is_recorded_in_the_plan_result(self):
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", EMPTY_OUTDATED, EMPTY_OUTDATED]
        plan = workflow.preview(self.store, self.t, runner=self.scripted(outputs, formulae="libheif 1.23.7\n"))
        probe = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", '{"formulae": [{"name": "libheif", "full_name": "libheif", "installed": [{"version": "1.23.7"}]}]}', ""]
        def failing(t, argv, **kwargs):
            if argv[-2:] == ["upgrade", "--cask"]:
                raise Error("nope")
            return probe.pop(0) if probe else ''
        with self.assertRaises(Error):
            workflow.apply(self.store, plan["id"], yes=True, runner=failing, request=lambda u, b=None: {})
        saved = json.loads(self.store.db.execute("SELECT result FROM plans WHERE id=?", (plan["id"],)).fetchone()[0])
        self.assertIn("brew upgrade --cask", saved["failed_step"])
        self.assertNotIn("nope", json.dumps(saved))  # raw tool text stays out of history

    def test_stable_host_clears_a_scanned_formula_without_a_change_warning(self):
        self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7"), self.finding("lame", "3.100")],
                                             complete=True, checked=2))
        report = self.check(self.INSTALLED, self.scan([], skipped=["lame"], checked=1))
        # The scanned formula clears; the skipped one keeps its finding for this version.
        self.assertEqual([f["advisory"] for f in report["findings"]], ["OSV-2020-2308"])
        self.assertEqual(report["findings"][0]["state"], "unknown")
        self.assertIsNone(report["update_error"])
        self.assertNotIn("changed_during_scan", report["coverage"])
        self.assertFalse(any("changed or could not be re-read" in w for w in report["warnings"]))
        self.assertIn("finding_no_longer_detected", [e["kind"] for e in self.store.events()])

    def test_an_unloadable_formula_keg_is_retired_neither_nor_credited_clean(self):
        # The keg stays in the Cellar but its formula can no longer be loaded (untap):
        # `brew info --installed` omits it while `brew list` still shows it. The finding
        # stays unknown; the check must not report the keg as resolved.
        self.check(self.INSTALLED + "ghost 1.0\n",
                   self.scan([self.finding("ghost", "1.0")], complete=True, checked=3))
        report = self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")],
                                                      complete=True, checked=2),
                            unloadable=["ghost"])
        states = {f["package"]: f["state"] for f in report["findings"]}
        self.assertEqual(states.get("ghost"), "unknown")
        self.assertTrue(any("not scanned by Homebrew" in w for w in report["warnings"]))

    def test_an_untapped_formula_keg_keeps_its_prior_finding_unknown(self):
        # A third-party formula's keg stays installed after its tap is removed: brew info
        # omits it, brew list still shows it, and the finding recorded under the
        # tap-qualified identity stays unknown instead of being retired.
        taps = {"ghost": "acme/x/ghost"}
        self.check(self.INSTALLED + "ghost 1.0\n",
                   self.scan([self.finding("acme/x/ghost", "1.0")], complete=True, checked=3),
                   taps=taps)
        report = self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")],
                                                      complete=True, checked=2),
                            unloadable=["ghost"])
        states = {f["package"]: f["state"] for f in report["findings"]}
        self.assertEqual(states.get("ghost"), "unknown")
        self.assertNotIn("finding_no_longer_detected", [e["kind"] for e in self.store.events()])

    def test_a_tap_swap_does_not_inherit_the_removed_formula_advisory(self):
        # libheif (strukturag tap) is replaced by another tap's formula of the same short
        # name and version; the scanner skips it, and the swap is caught by comparing the
        # tap-qualified identity across the scan.
        taps = {"libheif": "strukturag/libheif"}
        row = self.finding("strukturag/libheif", "1.23.7")
        self.check(self.INSTALLED, self.scan([row], skipped=["lame"]), taps=taps)
        # Between checks the formula is replaced by another tap's build of the same name
        # and version. The next check scans both formulae clean; the prior finding's
        # tap-qualified identity no longer matches, so it retires instead of describing
        # the replacement.
        swapped = dict(taps, libheif="other/libheif")
        report = self.check(self.INSTALLED, self.scan([], complete=True, checked=2), taps=swapped)
        self.assertEqual(report["findings"], [])
        self.assertIn("finding_no_longer_detected", [e["kind"] for e in self.store.events()])

    def test_uninstalled_formula_finding_is_retired(self):
        self.check(self.INSTALLED, self.scan([self.finding("lame", "3.100")], complete=True, checked=2))
        report = self.check("libheif 1.23.7\n", self.scan([], complete=True))
        self.assertEqual(report["findings"], [])
        self.assertIn("finding_no_longer_detected", [e["kind"] for e in self.store.events()])

    def test_no_scanner_is_an_incomplete_advisory_check(self):
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "install update\n", EMPTY_OUTDATED, EMPTY_OUTDATED]
        report = workflow.check(self.store, self.t, runner=self.scripted(outputs, formulae=self.INSTALLED),
                                request=lambda url, body=None: {})
        self.assertFalse(report["advisory_check_ok"])
        self.assertFalse(report["coverage"]["scanner"])
        self.assertEqual(report["coverage"]["retained"], ["lame", "libheif"])

    def test_offline_skips_the_scan_and_marks_the_check_incomplete(self):
        self.check(self.INSTALLED, self.scan([self.finding("libheif", "1.23.7")], complete=True, checked=2))
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", ""]
        report = workflow.check(self.store, self.t, offline=True,
                                runner=self.scripted(outputs, formulae=self.INSTALLED),
                                request=lambda url, body=None: {})
        self.assertFalse(report["advisory_check_ok"])
        self.assertTrue(report["coverage"]["deferred"])
        self.assertTrue(any("offline mode" in w for w in report["warnings"]))
        self.assertEqual(len(self.calls), 7)  # probe + inventory (info + list + cask); no scan, no outdated

    def test_scan_findings_for_uninstalled_versions_are_dropped(self):
        report = self.check(self.INSTALLED, self.scan([self.finding("libheif", "9.9.9")], complete=True, checked=2))
        self.assertEqual(report["findings"], [])
        self.assertTrue(any("changed version between collection" in w for w in report["warnings"]))
        self.assertFalse(any("{'" in w for w in report["warnings"]))  # no raw set literals

    def test_unscanned_formula_keeps_prior_finding_as_unknown(self):
        self.check(self.INSTALLED,
                   self.scan([self.finding("lame", "3.100", "OSV-2020-9999")], complete=True, checked=2))
        report = self.check("libheif 1.24.0\nlame 3.100\n", self.scan([], skipped=["lame"]))
        self.assertEqual([f["advisory"] for f in report["findings"]], ["OSV-2020-9999"])
        self.assertEqual(report["findings"][0]["state"], "unknown")

    def test_brew_commands_refresh_then_upgrade_by_half(self):
        t = adapters.target("laptop", "brew")
        self.assertEqual(adapters.commands(t),
                         [adapters.brew_env("brew", "update"),
                          adapters.brew_env("brew", "upgrade", "--formula", cleanup=False),
                          adapters.brew_env("brew", "upgrade", "--cask", cleanup=False)])

    def test_brew_outdated_keeps_same_named_formula_and_cask_apart(self):
        plain = json.dumps({"formulae": [{"name": "tool", "installed_versions": ["1.0"],
                                          "current_version": "1.1", "pinned": False, "pinned_version": None}],
                            "casks": []})
        greedy = json.dumps({"formulae": [{"name": "tool", "installed_versions": ["1.0"],
                                           "current_version": "1.1", "pinned": False, "pinned_version": None}],
                             "casks": [{"name": "tool", "installed_versions": ["2.0"],
                                        "current_version": "2.1", "pinned": False, "pinned_version": None}]})
        rows = adapters.brew_outdated(self.t, self.scripted([plain, greedy]))
        self.assertEqual([(r["ecosystem"], r["package"]) for r in rows],
                         [("Homebrew", "tool"), ("Homebrew-cask", "tool")])
        formula, cask = rows
        self.assertTrue(cask["greedy_only"])
        self.assertNotIn("greedy_only", formula)

    def test_brew_outdated_rejects_non_string_versions(self):
        bad = json.dumps({"formulae": [{"name": "x", "installed_versions": ["1"],
                                        "current_version": 1e400, "pinned": False, "pinned_version": None}],
                          "casks": []})
        with self.assertRaises(Error):
            adapters.brew_outdated(self.t, self.scripted([bad]))

    def test_brew_outdated_marks_greedy_only_and_held(self):
        plain = json.dumps({"formulae": [{"name": "pydantic", "installed_versions": ["2.14.3"],
                                          "current_version": "2.14.4", "pinned": False, "pinned_version": None},
                                         {"name": "openssl@3", "installed_versions": ["3.5.8"],
                                          "current_version": "3.5.9", "pinned": True, "pinned_version": "3.5.8"}],
                            "casks": []})
        greedy = json.dumps({"formulae": [{"name": "pydantic", "installed_versions": ["2.14.3"],
                                           "current_version": "2.14.4", "pinned": False, "pinned_version": None},
                                          {"name": "openssl@3", "installed_versions": ["3.5.8"],
                                           "current_version": "3.5.9", "pinned": True, "pinned_version": "3.5.8"}],
                             "casks": [{"name": "1password", "installed_versions": ["8.11"],
                                        "current_version": "8.12.46", "pinned": False, "pinned_version": None}]})
        rows = adapters.brew_outdated(self.t, self.scripted([plain, greedy]))
        self.assertEqual([r["package"] for r in rows], ["1password", "openssl@3", "pydantic"])
        self.assertTrue(next(r for r in rows if r["package"] == "1password")["greedy_only"])
        held = next(r for r in rows if r["package"] == "openssl@3")
        self.assertTrue(held["held"])
        self.assertEqual(held["held_version"], "3.5.8")
        self.assertNotIn("self_updating", rows[0])

    def test_root_target_is_refused_before_anything_runs(self):
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "0\n"]
        with self.assertRaises(Error) as caught:
            workflow.check(self.store, self.t, runner=self.scripted(outputs),
                           request=lambda url, body=None: {})
        self.assertIn("root", str(caught.exception))
        self.assertEqual(len(self.calls), 4)  # probe only; no inventory, no scan, no update

    def test_failed_cask_step_names_the_step_not_env(self):
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", EMPTY_OUTDATED, EMPTY_OUTDATED]
        plan = workflow.preview(self.store, self.t, runner=self.scripted(outputs, formulae="libheif 1.23.7\n"))
        # apply re-collects inventory first, then runs the three approved steps.
        probe = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", '{"formulae": [{"name": "libheif", "full_name": "libheif", "installed": [{"version": "1.23.7"}]}]}', ""]
        def failing(t, argv, **kwargs):
            if argv[-2:] == ["upgrade", "--cask"]:  # not `brew list --cask` during inventory
                raise Error("Command failed: brew upgrade --cask (exit 1)")
            return probe.pop(0) if probe else ''
        with self.assertRaises(Error) as caught:
            workflow.apply(self.store, plan["id"], yes=True, runner=failing,
                           request=lambda url, body=None: {})
        self.assertIn("brew upgrade --cask", str(caught.exception))
        self.assertNotIn("env PATH", str(caught.exception))
        self.assertEqual(self.store.db.execute("SELECT status FROM plans WHERE id=?", (plan["id"],)).fetchone()[0],
                         "needs_attention")

    def test_text_report_shows_held_and_default_list_markers(self):
        report = {"target": self.t, "packages": [adapters.package("libheif", "1.23.7", "Homebrew")],
                  "findings": [], "context": {},
                  "updates": [{"package": "openssl@3", "candidate": "3.5.9", "ecosystem": "Homebrew",
                               "held": True, "held_version": "3.5.8"},
                              {"package": "1password", "candidate": "8.12.46", "ecosystem": "Homebrew-cask",
                               "greedy_only": True, "reason": "Not in the default outdated list: excluded by Homebrew, or it became outdated between the two calls"}],
                  "warnings": [], "advisory_check_ok": True, "evidence": [], "update_error": None,
                  "coverage": {"scanner": True, "checked": 1, "complete": True, "skipped": [],
                               "unscanned": {}, "scanned": ["libheif"], "retained": []},
                  "at": 0}
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            cli.display([{"target": self.t, "last_attempt": None, "report": report, "pending_updates": []}],
                        False, show_all=True)
        plain = buffer.getvalue()
        self.assertIn("[held 3.5.8]", plain)
        self.assertIn("[not in default upgrade]", plain)

    def test_preview_warns_about_casks(self):
        outputs = ["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", EMPTY_OUTDATED, EMPTY_OUTDATED]
        plan = workflow.preview(self.store, self.t, runner=self.scripted(outputs, formulae="libheif 1.23.7\n"))
        self.assertIn("Cask upgrades", plan["scope"])


TARGET = adapters.target("laptop", "brew")


class BrewScanTests(unittest.TestCase):
    def scripted(self, outputs, calls=None, seen=(), aliases=None, formulae=""):
        outputs = list(outputs)
        self.calls = [] if calls is None else calls
        state = {"seen": set(seen), "versions": {}}
        for line in formulae.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                state["seen"].add(parts[0])
                state["versions"][parts[0]] = state["versions"].get(parts[0], []) + parts[1:]
        full = dict(aliases or {})
        def run(t, argv, **kwargs):
            self.calls.append((argv, kwargs))
            # `brew info --installed` knows exactly what the fixture installed.
            if "--installed" in argv:
                return json.dumps({"formulae": [{"name": name, "full_name": full.get(name, name),
                                                 "installed": [{"version": v} for v in state["versions"].get(name, ["1"])]}
                                                for name in sorted(state["seen"])]})
            if "list" in argv and "--formula" in argv and "--versions" in argv:
                return "".join(f"{name} {' '.join(state['versions'].get(name, ['1']))}\n"
                               for name in sorted(state["seen"]))
            if not outputs:
                raise AssertionError("Unexpected command: " + json.dumps(argv))
            return outputs.pop(0)
        return run

    def packages(self, *rows):
        return [adapters.package(name, version, "Homebrew") for name, version in rows]

    def test_partial_scan_reports_findings_and_coverage(self):
        rows = self.packages(("libheif", "1.23.7"), ("lame", "3.100"))
        run = self.scripted(["vulns update install\n", SCAN_PARTIAL], seen=("libheif", "lame"))
        findings, warnings, coverage = sources.brew_scan(TARGET, rows, run)
        self.assertEqual([f["advisory"] for f in findings], ["OSV-2020-2308"])
        self.assertEqual(findings[0]["installed"], "1.23.7")
        self.assertEqual(findings[0]["state"], "affected")
        self.assertEqual(findings[0]["repository"], "https://github.com/strukturag/libheif")
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["skipped"], ["lame", "playwright-cli"])
        self.assertEqual(coverage["unscanned"], {"wacli": "untrusted_tap"})
        self.assertEqual(coverage["scanned"], ["libheif"])
        self.assertTrue(any("absence of findings" in w for w in warnings))
        self.assertEqual(self.calls[1][1]["ok"], (0, 1))

    def test_finding_binds_to_version_not_name(self):
        # Two keg versions of the SAME formula, same advisory: one finding each, distinct keys.
        rows = self.packages(("python@3.12", "3.12.7"), ("python@3.12", "3.12.9"))
        scan = json.dumps({"findings": [
            {"formula": "python@3.12", "version": "3.12.7", "tag": "v3.12.7",
             "repo_url": "https://github.com/python/cpython",
             "vulnerabilities": [{"id": "GHSA-x", "severity": "HIGH", "summary": "s", "aliases": [], "fixed_versions": []}]},
            {"formula": "python@3.12", "version": "3.12.9", "tag": "v3.12.9",
             "repo_url": "https://github.com/python/cpython",
             "vulnerabilities": [{"id": "GHSA-x", "severity": "HIGH", "summary": "s", "aliases": [], "fixed_versions": []}]}],
            "skipped_formulae": [], "checked": 1, "complete": True,
            "outdated_without_sbom": [], "unscanned_formulae": {}})
        findings, _, _ = sources.brew_scan(TARGET, rows, self.scripted(["vulns\n", scan], seen=("python@3.12",)))
        self.assertEqual(sorted(f["installed"] for f in findings), ["3.12.7", "3.12.9"])
        self.assertEqual(len({f["key"] for f in findings}), 2)

    def test_missing_vulns_command_is_a_coverage_gap(self):
        findings, warnings, coverage = sources.brew_scan(TARGET, self.packages(("x", "1")),
                                                         self.scripted(["install update\n"]))
        self.assertEqual(findings, [])
        self.assertFalse(coverage["scanner"])
        self.assertEqual(coverage["scanned"], [])
        self.assertEqual(coverage["retained"], ["x"])
        self.assertTrue(any("no vulnerability scanner" in w for w in warnings))

    def test_offline_defers_the_scan_without_touching_the_runner(self):
        findings, warnings, coverage = sources.brew_scan(TARGET, self.packages(("x", "1")),
                                                         self.scripted([]), offline=True)
        self.assertEqual(findings, [])
        self.assertTrue(coverage["deferred"])
        self.assertEqual(coverage["retained"], ["x"])
        self.assertEqual(self.calls, [])
        self.assertTrue(any("offline mode" in w for w in warnings))

    def test_numeric_overflow_severity_does_not_reach_the_store(self):
        bad = json.dumps({"findings": [{"formula": "x", "version": "1", "tag": "v1",
                                       "repo_url": "https://example.com/x",
                                       "vulnerabilities": [{"id": "OSV-1", "severity": 1e400, "summary": "s",
                                                            "aliases": [], "fixed_versions": []}]}],
                          "skipped_formulae": [], "checked": 1, "complete": True,
                          "outdated_without_sbom": [], "unscanned_formulae": {}})
        with self.assertRaises(Error):
            sources.brew_scan(TARGET, self.packages(("x", "1")), self.scripted(["vulns\n", bad], seen=("x",)))

    def test_string_fixed_versions_is_rejected(self):
        bad = json.dumps({"findings": [{"formula": "x", "version": "1", "tag": "v1",
                                       "repo_url": "https://example.com/x",
                                       "vulnerabilities": [{"id": "OSV-1", "severity": "LOW", "summary": "s",
                                                            "aliases": [], "fixed_versions": "1.2.3"}]}],
                          "skipped_formulae": [], "checked": 1, "complete": True,
                          "outdated_without_sbom": [], "unscanned_formulae": {}})
        with self.assertRaises(Error):
            sources.brew_scan(TARGET, self.packages(("x", "1")), self.scripted(["vulns\n", bad], seen=("x",)))

    def test_a_stale_name_shadowed_by_a_tap_claims_no_coverage(self):
        # The stale entry names core `foo`; the inventory knows foo only as
        # acme/tools/foo. The checked slot cannot be credited to the tapped keg.
        t = TARGET
        scan = json.dumps({"findings": [], "skipped_formulae": [], "checked": 2, "complete": True,
                           "outdated_without_sbom": ["foo"], "unscanned_formulae": {}})
        run = self.scripted(["vulns\n", scan], seen=("foo", "real"),
                            aliases={"foo": "acme/tools/foo"}, formulae="foo 1\nreal 1\n")
        rows = []
        for name, version in (("foo", "1"), ("real", "1")):
            row = adapters.package(name, version, "Homebrew")
            if name == "real":
                row["tap"] = "acme/tools/foo"
            rows.append(row)
        findings, _, coverage = sources.brew_scan(t, rows, run)
        self.assertEqual(coverage["scanned"], [])
        self.assertTrue(coverage.get("unaccounted"))

    def test_a_stale_target_outside_the_inventory_claims_no_coverage(self):
        # The only checked slot belongs to a stale formula that is not installed; the
        # installed keg must not be credited clean.
        t = TARGET
        scan = json.dumps({"findings": [], "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": ["ghost"], "unscanned_formulae": {}})
        run = self.scripted(["vulns\n", scan], seen=("real",))
        findings, _, coverage = sources.brew_scan(t, self.packages(("real", "1")), run)
        self.assertEqual(coverage["scanned"], [])
        self.assertTrue(coverage.get("unaccounted"))

    def test_a_core_row_is_not_evidence_about_a_tapped_keg(self):
        # The inventory knows foo only as acme/tools/foo; a scanner row for core foo at
        # the same version contradicts the accounting and must not publish or clear.
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "foo", "version": "1", "tag": "v1",
                                        "repo_url": "https://example.com/foo",
                                        "vulnerabilities": [{"id": "OSV-1", "severity": "HIGH", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["vulns\n", scan], seen=("foo",),
                            aliases={"foo": "acme/tools/foo"})
        rows = self.packages(("foo", "1"))
        rows[0]["tap"] = "acme/tools/foo"
        findings, warnings, coverage = sources.brew_scan(t, rows, run)
        self.assertEqual(findings, [])
        self.assertTrue(coverage.get("unaccounted"))
        self.assertEqual(coverage["retained_versions"], [["acme/tools/foo", "1"]])

    def test_tap_qualified_full_name_resolves_to_the_inventory_name(self):
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "kenn-io/tap/agentsview", "version": "0.47.0",
                                         "tag": "v0.47.0", "repo_url": "https://github.com/kenn-io/agentsview",
                                         "vulnerabilities": [{"id": "OSV-7", "severity": "HIGH", "summary": "s",
                                                              "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            aliases={"agentsview": "kenn-io/tap/agentsview"},
                            formulae="agentsview 0.47.0\n")
        rows = adapters.inventory(t, run)
        findings, warnings, coverage = sources.brew_scan(t, rows, run)
        self.assertEqual([f["package"] for f in findings], ["agentsview"])
        self.assertEqual([f["tap"] for f in findings], ["kenn-io/tap/agentsview"])
        # Coverage names carry the tap-qualified identity.
        self.assertEqual(coverage["scanned"], ["kenn-io/tap/agentsview"])
        self.assertEqual(coverage["retained_versions"], [])
        self.assertFalse(any("changed version" in w for w in warnings))

    def test_a_multi_keg_formula_covers_only_the_keg_homebrew_scanned(self):
        # Homebrew scans one keg per formula (any_installed_prefix). An 8.0 finding stays
        # unknown while 9.0.2 is covered, even though the formula counts as checked.
        t = TARGET
        scan = json.dumps({"findings": [], "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            formulae="ffmpeg 8.0\nffmpeg 9.0.2\n")
        rows = adapters.inventory(t, run)
        findings, warnings, coverage = sources.brew_scan(t, rows, run)
        # A clean multi-keg assessment cannot identify the scanned keg, so nothing is covered.
        self.assertEqual(coverage["scanned"], [])
        self.assertEqual(sorted(coverage["retained_versions"]), [["ffmpeg", "8.0"], ["ffmpeg", "9.0.2"]])

    def test_a_matched_multi_keg_row_covers_only_its_own_keg(self):
        # ffmpeg 8.0 has an earlier finding; the scan reports only 9.0.2. The 8.0 keg keeps
        # its finding as unknown even though the formula counts as checked.
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "ffmpeg", "version": "9.0.2", "tag": "v9.0.2",
                                        "repo_url": "https://github.com/FFmpeg/FFmpeg",
                                        "vulnerabilities": [{"id": "OSV-9", "severity": "HIGH", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            formulae="ffmpeg 8.0\nffmpeg 9.0.2\n")
        rows = adapters.inventory(t, run)
        findings, warnings, coverage = sources.brew_scan(t, rows, run)
        self.assertEqual(sorted((f["installed"], f["upstream_version"]) for f in findings),
                         [("9.0.2", "9.0.2")])
        self.assertEqual(coverage["retained_versions"], [["ffmpeg", "8.0"]])
        self.assertTrue(any("other installed kegs" in w for w in warnings))

    def test_a_revision_suffix_keg_matches_its_upstream_version_row(self):
        # A revision-zero keg (1_2) and a revised one (1_2_1) are both upstream 1_2.
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "tool", "version": "1_2", "tag": "v1.2",
                                        "repo_url": "https://example.com/tool",
                                        "vulnerabilities": [{"id": "OSV-3", "severity": "HIGH", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            formulae="tool 1_2 1_2_1\n")
        rows = adapters.inventory(t, run)
        findings, _, coverage = sources.brew_scan(t, rows, run)
        # Keg 1_2 could be upstream 1 at revision 2, so it is ambiguous and stays unknown;
        # only the unambiguous 1_2_1 keg receives the finding.
        self.assertEqual([f["installed"] for f in findings], ["1_2_1"])
        self.assertEqual(coverage["retained_versions"], [["tool", "1_2"]])  # ambiguous keg stays unknown

    def test_a_revision_zero_keg_next_to_a_revised_one_is_not_ambiguous(self):
        # Homebrew's own parse: keg `1_2` IS upstream 1 revision 2, so a scan row for
        # upstream 1 correctly covers both kegs; a keg name with a trailing _<digits>
        # cannot be a separate upstream release under Homebrew's naming.
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "tool", "version": "1", "tag": "v1",
                                        "repo_url": "https://example.com/tool",
                                        "vulnerabilities": [{"id": "OSV-1", "severity": "HIGH", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            formulae="tool 1 1_2\n")
        rows = adapters.inventory(t, run)
        findings, _, coverage = sources.brew_scan(t, rows, run)
        self.assertEqual(sorted(f["installed"] for f in findings), ["1", "1_2"])
        self.assertEqual(coverage["retained_versions"], [])

    def test_brew_inventory_and_scan_agree_across_a_revision_suffix(self):
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "ffmpeg", "version": "9.0.2", "tag": "9.0.2",
                                        "repo_url": "https://github.com/FFmpeg/FFmpeg",
                                        "vulnerabilities": [{"id": "OSV-9", "severity": "HIGH", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 2, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            formulae="ffmpeg 9.0.2_1\nopenssl@3 3.5.8\n")
        rows = adapters.inventory(t, run)
        findings, warnings, coverage = sources.brew_scan(t, rows, run)
        self.assertEqual([f["installed"] for f in findings], ["9.0.2_1"])  # the keg's version
        self.assertEqual(findings[0]["upstream_version"], "9.0.2")
        self.assertEqual(coverage["scanned"], ["ffmpeg", "openssl@3"])
        self.assertFalse(any("changed version" in w for w in warnings))

    def test_each_installed_revision_of_one_formula_gets_its_own_finding(self):
        t = TARGET
        scan = json.dumps({"findings": [{"formula": "ffmpeg", "version": "9.0.2", "tag": "9.0.2",
                                        "repo_url": "https://github.com/FFmpeg/FFmpeg",
                                        "vulnerabilities": [{"id": "OSV-9", "severity": "HIGH", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        run = self.scripted(["Darwin\n", "arm64\n", "15.3.1\n", "501\n", "", "vulns\n", scan],
                            formulae="ffmpeg 9.0.2 9.0.2_1\n")
        rows = adapters.inventory(t, run)
        findings, _, _ = sources.brew_scan(t, rows, run)
        self.assertEqual(sorted(f["installed"] for f in findings), ["9.0.2", "9.0.2_1"])
        self.assertEqual(len({f["key"] for f in findings}), 2)

    def test_checked_must_be_a_nonnegative_int(self):
        for value in (True, -1, "1"):
            bad = json.dumps({"findings": [], "skipped_formulae": [], "checked": value, "complete": True,
                              "outdated_without_sbom": [], "unscanned_formulae": {}})
            with self.assertRaises(Error):
                sources.brew_scan(TARGET, self.packages(("x", "1")), self.scripted(["vulns\n", bad], seen=("x",)))

    def test_scan_count_that_cannot_account_for_the_installed_set_claims_no_coverage(self):
        rows = self.packages(("x", "1"), ("y", "1"))
        two = [{"formula": name, "version": "1", "tag": "v1", "repo_url": "https://example.com/" + name,
                "vulnerabilities": [{"id": "OSV-" + name, "severity": "LOW", "summary": "s",
                                     "aliases": [], "fixed_versions": []}]} for name in ("x", "y")]
        bad = json.dumps({"findings": two, "skipped_formulae": [], "checked": 1, "complete": True,
                          "outdated_without_sbom": [], "unscanned_formulae": {}})
        findings, warnings, coverage = sources.brew_scan(TARGET, rows, self.scripted(["vulns\n", bad], seen=("x", "y")))
        self.assertEqual(findings, [])
        self.assertTrue(coverage["unaccounted"])
        self.assertEqual(coverage["scanned"], [])
        self.assertEqual(coverage["retained"], ["x", "y"])
        self.assertTrue(any("does not match the installed set" in w for w in warnings))

    def test_empty_or_multiline_summary_does_not_discard_the_scan(self):
        scan = json.dumps({"findings": [{"formula": "x", "version": "1", "tag": "v1",
                                        "repo_url": "https://example.com/x",
                                        "vulnerabilities": [{"id": "OSV-1", "severity": "LOW",
                                                             "summary": "", "aliases": [],
                                                             "fixed_versions": []},
                                                            {"id": "OSV-2", "severity": "LOW",
                                                             "summary": "line one\nline two",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        findings, _, _ = sources.brew_scan(TARGET, self.packages(("x", "1")),
                                           self.scripted(["vulns\n", scan], seen=("x",)))
        self.assertEqual(sorted(f["advisory"] for f in findings), ["OSV-1", "OSV-2"])
        self.assertEqual(findings[1]["summary"], "line one line two")

    def test_repository_url_credentials_and_query_are_stripped(self):
        scan = json.dumps({"findings": [{"formula": "x", "version": "1", "tag": "v1",
                                        "repo_url": "https://token@github.com/example/x?secret=hunter2",
                                        "vulnerabilities": [{"id": "OSV-1", "severity": "LOW", "summary": "s",
                                                             "aliases": [], "fixed_versions": []}]}],
                           "skipped_formulae": [], "checked": 1, "complete": True,
                           "outdated_without_sbom": [], "unscanned_formulae": {}})
        findings, _, _ = sources.brew_scan(TARGET, self.packages(("x", "1")),
                                           self.scripted(["vulns\n", scan], seen=("x",)))
        self.assertEqual(findings[0]["repository"], "https://github.com/example/x")
        self.assertEqual(sources.strip_credentials("https://github.com/a/b#frag"), "https://github.com/a/b#frag")
        self.assertEqual(sources.strip_credentials("https://u:p@gitlab.com/a/b"), "https://gitlab.com/a/b")
        self.assertEqual(sources.strip_credentials("https://u:p@[2001:db8::1]/r?ref=main"),
                         "https://[2001:db8::1]/r")

    def test_dict_findings_field_is_rejected(self):
        bad = json.dumps({"findings": {}, "skipped_formulae": [], "checked": 1, "complete": True,
                          "outdated_without_sbom": [], "unscanned_formulae": {}})
        with self.assertRaises(Error):
            sources.brew_scan(TARGET, self.packages(("x", "1")), self.scripted(["vulns\n", bad], seen=("x",)))

    def test_pwn_watch_matches_formulae_but_not_colliding_cask_names(self):
        catalog = {"generatedAt": "2026-11-20T00:00:00Z", "incidents": [
            {"slug": "gemini-thing", "title": "Gemini problem", "product": "Gemini", "severity": "high",
             "patchStatus": "patched", "updatedAt": "2026-11-19T00:00:00Z", "isExample": False,
             "category": "supply-chain", "status": "live", "tags": ["gemini"], "cveIds": []},
            {"slug": "openssl-thing", "title": "OpenSSL problem", "product": "OpenSSL", "severity": "high",
             "patchStatus": "patched", "updatedAt": "2026-11-19T00:00:00Z", "isExample": False,
             "category": "supply-chain", "status": "live", "tags": ["openssl@3"], "cveIds": []}]}
        packages = [adapters.package("gemini", "2.10.1", "Homebrew-cask"),
                    adapters.package("openssl@3", "3.5.9", "Homebrew")]
        matched = sources.pwn_context(packages, [], catalog)
        self.assertEqual([m["id"] for m in matched], ["openssl-thing"])

    def test_malformed_scan_output_fails_loudly(self):
        with self.assertRaises(Error):
            sources.brew_scan(TARGET, self.packages(("x", "1")), self.scripted(["vulns\n", "not json"], seen=("x",)))

    def test_withdrawn_or_unknown_shapes_are_rejected(self):
        bad = json.dumps({"findings": [{"formula": "x", "version": "1", "tag": "v1",
                                        "repo_url": "https://example.com/x", "vulnerabilities": [{}]}],
                          "skipped_formulae": [], "checked": 1, "complete": True,
                          "outdated_without_sbom": [], "unscanned_formulae": {}})
        with self.assertRaises(Error):
            sources.brew_scan(TARGET, self.packages(("x", "1")), self.scripted(["vulns\n", bad], seen=("x",)))


if __name__ == "__main__":
    unittest.main()
