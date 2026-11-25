import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netwatch import scan


def tree(root: Path, files: dict[str, str]):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


class WalkTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def test_walk_stops_at_repo_root_and_does_not_descend(self):
        tree(self.root, {
            "repo/.git/HEAD": "", "repo/sub/pyproject.toml": "",
            "other/pyvenv.cfg": "", "other/uv-receipt.toml": "",
        })
        items = list(scan.walk(self.root))
        self.assertEqual([i.path.relative_to(self.root).as_posix() for i in items], ["other", "repo"])
        self.assertEqual([i.lane for i in items], ["user", "repo"])

    def test_user_lane_needs_a_manager_receipt_not_just_a_venv(self):
        tree(self.root, {"v/pyvenv.cfg": "", "plain/README.md": ""})
        items = list(scan.walk(self.root))
        self.assertEqual([i.lane for i in items], ["unclassified"])
        self.assertIn("manager receipt", items[0].evidence[0])

    def test_pipx_marker_also_marks_a_user_lane_venv(self):
        tree(self.root, {"v/pyvenv.cfg": "", "v/pipx_metadata.json": "{}"})
        self.assertEqual([i.lane for i in list(scan.walk(self.root))], ["user"])

    def test_skip_list_keeps_the_walk_out_of_noise(self):
        tree(self.root, {"node_modules/p/pyvenv.cfg": "", ".venv/pyvenv.cfg": "",
                         "ok/pyvenv.cfg": "", "ok/uv-receipt.toml": ""})
        paths = [i.path.name for i in scan.walk(self.root)]
        self.assertEqual(paths, ["ok"])

    def test_depth_bounds_the_walk(self):
        tree(self.root, {"a/b/c/d/pyvenv.cfg": "", "a/b/c/d/uv-receipt.toml": ""})
        self.assertEqual(list(scan.walk(self.root, depth=2)), [])
        self.assertEqual([i.path.name for i in scan.walk(self.root, depth=5)], ["d"])

    def test_exclude_patterns_are_honoured(self):
        tree(self.root, {"skip/pyvenv.cfg": "", "skip/uv-receipt.toml": "",
                         "keep/pyvenv.cfg": "", "keep/uv-receipt.toml": ""})
        self.assertEqual([i.path.name for i in scan.walk(self.root, excludes=("skip",))], ["keep"])

    def test_symlinked_directories_are_not_followed(self):
        tree(self.root, {"real/pyvenv.cfg": "", "real/uv-receipt.toml": ""})
        (self.root / "link").symlink_to(self.root / "real")
        self.assertEqual([i.path.name for i in scan.walk(self.root)], ["real"])


class ListOnlyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def test_list_runs_no_git_no_gh_and_opens_no_database(self):
        tree(self.root, {"repo/.git/HEAD": ""})
        with mock.patch("subprocess.run") as run, mock.patch("netwatch.store.Store") as store:
            scan.list_only(self.root, db=self.root / "state.db")
        run.assert_not_called()
        store.assert_not_called()

    def test_list_renders_lane_and_says_tool_enumeration_was_skipped(self):
        tree(self.root, {"repo/.git/HEAD": "", "v/pyvenv.cfg": "", "v/uv-receipt.toml": ""})
        out = scan.list_only(self.root, db=self.root / "state.db")
        self.assertIn("repo-lane", out)
        self.assertIn("user-lane", out)
        self.assertIn("tool enumeration skipped in --list", out)

    def test_list_reports_the_classification_counts(self):
        tree(self.root, {"repo/.git/HEAD": "", "v/pyvenv.cfg": "", "v/uv-receipt.toml": ""})
        summary = scan.summary(list(scan.walk(self.root)))
        self.assertIn("1 repo", summary)
        self.assertIn("1 user-lane", summary)


if __name__ == "__main__":
    unittest.main()
