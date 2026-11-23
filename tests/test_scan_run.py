import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netwatch import scan, store as store_module, tickets


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=a@b", "-c", "user.name=a", *args],
                   check=True, capture_output=True)


class OwnedTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.repo = self.root / "r"
        self.repo.mkdir()
        git(self.repo, "init", "-q")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_owned_true_for_github_remote_under_a_handle(self):
        git(self.repo, "remote", "add", "origin", "git@github.com:jesserobbins/netwatch.git")
        self.assertTrue(scan.owned(self.repo, {"jesserobbins"}))

    def test_owned_false_for_another_owner(self):
        git(self.repo, "remote", "add", "origin", "https://github.com/lhl/netwatch.git")
        self.assertFalse(scan.owned(self.repo, {"jesserobbins"}))

    def test_owned_false_for_a_non_github_host(self):
        git(self.repo, "remote", "add", "origin", "https://gitlab.com/jesserobbins/x.git")
        self.assertFalse(scan.owned(self.repo, {"jesserobbins"}))

    def test_owned_false_without_a_remote(self):
        self.assertFalse(scan.owned(self.repo, {"jesserobbins"}))


class HandleTests(unittest.TestCase):
    def test_explicit_handles_and_the_gh_login_are_both_accepted(self):
        class Result:
            returncode = 0
            stdout = "jesserobbins\n"
        self.assertEqual(scan.handles_from(["friend"], runner=lambda argv, **kw: Result()),
                         {"friend", "jesserobbins"})

    def test_a_missing_gh_leaves_the_explicit_handles(self):
        def explode(argv, **kw):
            raise FileNotFoundError("gh")
        self.assertEqual(scan.handles_from(["friend"], runner=explode), {"friend"})

    def test_a_failed_gh_call_is_not_fatal(self):
        class Result:
            returncode = 1
            stdout = ""
        self.assertEqual(scan.handles_from([], runner=lambda argv, **kw: Result()), set())


class RunTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        self.owned = self.root / "owned"
        self.foreign = self.root / "foreign"
        for repo, url in ((self.owned, "https://github.com/jesserobbins/x.git"),
                          (self.foreign, "https://github.com/lhl/y.git")):
            repo.mkdir()
            git(repo, "init", "-q")
            git(repo, "remote", "add", "origin", url)
            (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "init")
        self.venv = self.root / "tool"
        self.venv.mkdir()
        (self.venv / "pyvenv.cfg").write_text("")
        (self.venv / "uv-receipt.toml").write_text(
            '[tool]\nrequirements = [{ name = "tool" }]\nentrypoints = []\n')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_scan(self, **kw):
        store = store_module.Store(self.state)
        try:
            return scan.run(store, self.root, handles={"jesserobbins"},
                            request=lambda url, body=None: {"vulns": []}, **kw)
        finally:
            store.close()

    def test_scan_persists_a_run_and_returns_its_id(self):
        result = self.run_scan()
        self.assertEqual(result["run"], 1)
        self.assertIn("scan run 1:", result["summary"])
        store = store_module.Store(self.state)
        rows = store.db.execute("SELECT lane, ordinal, item_path FROM scan_records ORDER BY lane, ordinal").fetchall()
        self.assertEqual([(r[0], r[1]) for r in rows], [("repo", 1), ("repo", 2), ("user", 1)])
        store.close()

    def test_scan_writes_a_ticket_only_into_owned_repos(self):
        result = self.run_scan()
        self.assertTrue((self.owned / ".netwatch").is_file())
        self.assertFalse((self.foreign / ".netwatch").exists())
        self.assertEqual([Path(t["path"]).resolve() for t in result["tickets"]],
                         [self.owned.resolve()])
        self.assertEqual([Path(s["path"]).resolve() for s in result["skipped"]],
                         [self.foreign.resolve()])

    def test_scan_records_the_root_normalized(self):
        self.run_scan()
        store = store_module.Store(self.state)
        root = store.db.execute("SELECT root FROM scan_runs WHERE id=1").fetchone()[0]
        self.assertEqual(Path(root).resolve(), self.root.resolve())
        store.close()

    def test_report_writes_a_ticket_into_a_repo_it_does_not_own(self):
        store = store_module.Store(self.state)
        try:
            outcome = scan.report(store, self.foreign, request=lambda url, body=None: {"vulns": []})
        finally:
            store.close()
        self.assertEqual(outcome["status"], "written")
        self.assertTrue((self.foreign / ".netwatch").is_file())

    def test_a_repo_with_locked_packages_scans_with_the_cache(self):
        (self.owned / "package.json").write_text('{"name":"x"}')
        (self.owned / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/minimist": {"version": "1.2.0"}},
        }))
        git(self.owned, "add", "-A")
        git(self.owned, "commit", "-qm", "lockfile")
        queried = []

        def request(url, body=None):
            if isinstance(body, dict) and "queries" in body:
                # the run-wide screen: flag every queried package for a detail pass
                return {"results": [{"vulns": [{"id": "GHSA-example"}]}
                                   for _ in body["queries"]]}
            queried.append(body["package"]["name"])
            return {"vulns": [{"id": "GHSA-example", "affected": [{
                "package": {"ecosystem": "npm", "name": "minimist"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]}]}

        store = store_module.Store(self.state)
        try:
            result = scan.run(store, self.root, handles={"jesserobbins"}, request=request)
        finally:
            store.close()
        self.assertEqual(queried, ["minimist"])
        self.assertEqual(result["advisory_requests"], {"screen": 1, "detail": 1})
        self.assertEqual([Path(t["path"]).resolve() for t in result["tickets"]],
                         [self.owned.resolve()])
        self.assertTrue((self.owned / ".netwatch").is_file())

    def test_scan_does_not_write_a_ticket_when_collection_yields_nothing(self):
        store = store_module.Store(self.state)
        try:
            with mock.patch.object(tickets, "inspect", return_value=(
                    {"netwatch": 1, "generated": "x", "collection": "incomplete",
                     "error": "both parsers failed", "findings": [], "leads": []},
                    [], ["both parsers failed"])):
                result = scan.run(store, self.root, handles={"jesserobbins"},
                                  request=lambda url, body=None: {"vulns": []})
        finally:
            store.close()
        self.assertFalse((self.owned / ".netwatch").exists())
        self.assertEqual(result["tickets"], [])


if __name__ == "__main__":
    unittest.main()


class ProgressTests(unittest.TestCase):
    """A scan of a big root says what it is doing instead of going quiet."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        (self.root / "tools").mkdir()
        for name in ("a", "b"):
            venv = self.root / "tools" / name
            (venv / "bin").mkdir(parents=True)
            (venv / "pyvenv.cfg").write_text("")
            (venv / "uv-receipt.toml").write_text(
                '[tool]\nrequirements = [{ name = "%s" }]\nentrypoints = []\n' % name)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_one_progress_line_per_item_and_a_leading_summary(self):
        messages = []
        store = store_module.Store(self.state)
        try:
            scan.run(store, self.root, handles=set(),
                     request=lambda u, b=None: {"vulns": []},
                     progress=messages.append)
        finally:
            store.close()
        self.assertTrue(messages[0].startswith("scanning "), messages[0])
        self.assertIn("2 items", messages[0])
        self.assertEqual([m.split()[0] for m in messages[1:]], ["[1/2]", "[2/2]"])
        self.assertIn("user", messages[1])

    def test_quiet_means_the_caller_passes_no_progress(self):
        store = store_module.Store(self.state)
        try:
            result = scan.run(store, self.root, handles=set(),
                              request=lambda u, b=None: {"vulns": []})
        finally:
            store.close()
        self.assertIn("scan run 1", result["summary"])


class GitReadFailureTests(unittest.TestCase):
    """A checkout whose git reads stall or fail must not stop the scan."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.repo = self.root / "repo"
        (self.repo / ".git").mkdir(parents=True)
        (self.repo / "pyproject.toml").write_text("[project]\nname='x'\n")
        (self.repo / "uv.lock").write_text("")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_timed_out_git_read_is_recorded_as_incomplete(self):
        def hang(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 60)

        payload, incomplete = tickets.collect(self.repo, runner=hang,
                                              request=lambda u, b=None: {"vulns": []})
        self.assertEqual(payload["collection"], "incomplete")
        self.assertTrue(any("git" in reason for reason in incomplete), incomplete)

    def test_the_timeout_is_set_on_the_real_runner(self):
        with mock.patch.object(tickets.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            # the default runner is bound at definition time, so pass the patched one
            tickets.git(self.repo, "status", "--porcelain", runner=tickets.subprocess.run)
        self.assertEqual(run.call_args.kwargs.get("timeout"), tickets.GIT_TIMEOUT)
        self.assertIsNotNone(run.call_args.kwargs.get("timeout"))


class IncompleteReportingTests(unittest.TestCase):
    def test_a_repo_whose_reads_failed_is_named_in_the_summary(self):
        root = Path(tempfile.mkdtemp())
        repo = root / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / "pyproject.toml").write_text("[project]\nname='x'\n")
        (repo / "uv.lock").write_text("")
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin",
                        "https://github.com/jesserobbins/x.git"], check=True, capture_output=True)
        store = store_module.Store(root / "state.db")
        try:
            with mock.patch.object(scan, "owned", return_value=True), \
                    mock.patch.object(tickets, "git",
                                      side_effect=tickets.Error("git did not answer")):
                result = scan.run(store, root, handles={"jesserobbins"},
                                  request=lambda u, b=None: {"vulns": []})
        finally:
            store.close()
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual([Path(r["path"]).name for r in result["incomplete"]], ["repo"])


class ScreenedRunTests(unittest.TestCase):
    """One advisory screen covers the whole run; only what it flags gets a detail query."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.state = self.root / "state.db"
        self.repos = []
        for name, extra in (("one", ("left-pad", "1.0.0")), ("two", ())):
            repo = self.root / name
            repo.mkdir()
            git(repo, "init", "-q")
            git(repo, "remote", "add", "origin",
                "https://github.com/jesserobbins/%s.git" % name)
            (repo / "package.json").write_text('{"name":"%s"}' % name)
            packages = {"": {}, "node_modules/minimist": {"version": "1.2.0"}}
            if extra:
                packages["node_modules/" + extra[0]] = {"version": extra[1]}
            (repo / "package-lock.json").write_text(json.dumps(
                {"lockfileVersion": 3, "packages": packages}))
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "init")
            self.repos.append(repo)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run_scan(self, screen, **kw):
        store = store_module.Store(self.state)
        try:
            return scan.run(store, self.root, handles={"jesserobbins"},
                            request=lambda url, body=None: {"vulns": []},
                            screen=screen, **kw)
        finally:
            store.close()

    def test_the_screen_runs_once_for_the_whole_run_and_dedupes(self):
        # two repos locking the same package: one batch, minimist asked once in it
        batches = []

        def screen(queries):
            batches.append([(q["package"]["ecosystem"], q["package"]["name"]) for q in queries])
            return [[] for _ in queries]

        result = self.run_scan(screen)
        self.assertEqual(len(batches), 1)
        self.assertEqual(sorted(batches[0]), [("npm", "left-pad"), ("npm", "minimist")])
        self.assertEqual(len(set(batches[0])), len(batches[0]))      # no duplicates
        self.assertEqual(result["advisory_requests"], {"screen": 1, "detail": 0})

    def test_a_second_run_inside_the_hour_screens_nothing(self):
        calls = []

        def screen(queries):
            calls.append(list(queries))
            return [[] for _ in queries]

        first = self.run_scan(screen)
        second = self.run_scan(screen)
        self.assertEqual(first["advisory_requests"]["screen"], 1)
        self.assertEqual(second["advisory_requests"]["screen"], 0)
        self.assertEqual(len(calls), 1)

    def test_a_failed_screen_leaves_every_affected_repo_incomplete(self):
        def screen(queries):
            raise tickets.Error("OSV refused the batch")

        result = self.run_scan(screen)
        self.assertEqual(result["advisory_requests"]["screen"], 1)
        self.assertEqual([Path(r["path"]).name for r in result["incomplete"]], ["one", "two"])
        for row in result["incomplete"]:
            self.assertTrue(any("advisory screen failed" in reason for reason in row["reasons"]),
                            row["reasons"])

    def test_progress_announces_the_screening_before_the_screen_runs(self):
        # the announcement is what keeps a two-request wait from reading as a hang,
        # so it must precede the screen call; the outcome line stays exactly as ruled
        messages = []

        def screen(queries):
            messages.append("screen ran")
            return [[] for _ in queries]

        self.run_scan(screen, progress=messages.append)
        watched = [m for m in messages if m.startswith("advisories: ") or m == "screen ran"]
        self.assertEqual(watched, ["advisories: screening 2 packages (0 already cached)",
                                  "screen ran",
                                  "advisories: 2 packages screened in 1 requests, 0 need detail"])

    def test_a_fully_cached_scan_announces_nothing_to_screen(self):
        self.run_scan(lambda queries: [[] for _ in queries])   # warm the hour cache
        messages = []
        self.run_scan(lambda queries: [[] for _ in queries], progress=messages.append)
        self.assertEqual([m for m in messages if m.startswith("advisories: ")],
                         ["advisories: 2 packages screened in 0 requests, 0 need detail"])
