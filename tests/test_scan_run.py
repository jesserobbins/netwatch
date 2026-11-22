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

    def test_scan_does_not_write_a_ticket_when_collection_yields_nothing(self):
        store = store_module.Store(self.state)
        try:
            with mock.patch.object(tickets, "collect", return_value=(
                    {"netwatch": 1, "generated": "x", "collection": "incomplete",
                     "error": "both parsers failed", "findings": [], "leads": []},
                    ["both parsers failed"])):
                result = scan.run(store, self.root, handles={"jesserobbins"},
                                  request=lambda url, body=None: {"vulns": []})
        finally:
            store.close()
        self.assertFalse((self.owned / ".netwatch").exists())
        self.assertEqual(result["tickets"], [])


if __name__ == "__main__":
    unittest.main()
