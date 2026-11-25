import os
import shutil
import tempfile
import unittest
from pathlib import Path

from netwatch import pins


def make_venv(root: Path):
    venv = root / "v"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("")
    (venv / "bin" / "python").write_text("")
    return venv


def make_dist(venv: Path, name="tool", version="1.0", scripts=None):
    dist = venv / "lib" / "python3.12" / "site-packages" / ("%s-%s.dist-info" % (name, version))
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version))
    body = ["[console_scripts]"] + ["%s = %s" % (k, v) for k, v in (scripts or {}).items()]
    (dist / "entry_points.txt").write_text("\n".join(body) + "\n")
    return dist


def wrapper(venv, script, interpreter=None, target="tool.cli:main"):
    path = venv / "bin" / script
    path.write_text("#!/bin/sh\n'''exec' %s \"$0\" \"$@\"\n' '''\n# -*- coding: utf-8 -*-\nimport sys\nfrom %s import main\n"
                    % (interpreter or (venv / "bin" / "python"), target.split(":")[0]))
    path.chmod(0o755)
    return path


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)
        make_dist(self.venv, scripts={"tool": "tool.cli:main", "tool-extra": "tool.extra:main"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def statuses(self):
        return {row["script"]: row["status"] for row in pins.launchers(self.venv, self.venv / "bin", "tool")}

    def test_a_wrapper_inside_the_venv_is_healthy(self):
        wrapper(self.venv, "tool")
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        self.assertEqual(self.statuses(), {"tool": "ok", "tool-extra": "ok"})

    def test_a_missing_script_is_broken(self):
        wrapper(self.venv, "tool")
        self.assertEqual(self.statuses()["tool-extra"], "broken")

    def test_an_interpreter_outside_the_venv_is_broken(self):
        wrapper(self.venv, "tool", interpreter="/usr/bin/python3")
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        reported = pins.launchers(self.venv, self.venv / "bin", "tool")
        row = [r for r in reported if r["script"] == "tool"][0]
        self.assertEqual(row["status"], "broken")
        self.assertIn("outside", row["detail"])

    def test_a_dot_dot_escape_is_not_inside_the_venv(self):
        wrapper(self.venv, "tool", interpreter=str(self.venv / "bin" / ".." / ".." / "elsewhere" / "python"))
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        row = [r for r in pins.launchers(self.venv, self.venv / "bin", "tool") if r["script"] == "tool"][0]
        self.assertEqual(row["status"], "broken")

    def test_a_sibling_prefix_is_not_inside_the_venv(self):
        sibling = self.root / "v-other" / "bin"
        sibling.mkdir(parents=True)
        wrapper(self.venv, "tool", interpreter=sibling / "python")
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        row = [r for r in pins.launchers(self.venv, self.venv / "bin", "tool") if r["script"] == "tool"][0]
        self.assertEqual(row["status"], "broken")

    def test_a_trampoline_reads_the_interpreter_from_its_exec_line(self):
        wrapper(self.venv, "tool")
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        # the shebang is /bin/sh for these; only the exec line names the interpreter
        self.assertEqual(self.statuses()["tool"], "ok")

    def test_a_written_path_that_resolves_outside_the_venv_is_a_lead(self):
        alias = self.root / "alias"
        alias.mkdir()
        (alias / "python").write_text("")
        wrapper(self.venv, "tool", interpreter=alias / "python")
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        # the written path is not inside the venv at all -> broken, not a lead
        self.assertEqual(self.statuses()["tool"], "broken")

    def test_a_wrapper_that_invokes_another_entry_point_is_broken(self):
        path = wrapper(self.venv, "tool")
        path.write_text(path.read_text().replace("from tool.cli", "from something.else"))
        wrapper(self.venv, "tool-extra", target="tool.extra:main")
        row = [r for r in pins.launchers(self.venv, self.venv / "bin", "tool") if r["script"] == "tool"][0]
        self.assertEqual(row["status"], "broken")
        self.assertIn("does not invoke", row["detail"])


class EntryPointReadTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_only_the_registered_distributions_scripts_are_expected(self):
        make_dist(self.venv, name="tool", scripts={"tool": "tool.cli:main"})
        make_dist(self.venv, name="other", version="2.0", scripts={"other": "other.cli:main"})
        self.assertEqual(pins.entry_points(self.venv, "tool"), {"tool": "tool.cli:main"})

    def test_a_distribution_without_entry_points_declares_none(self):
        dist = make_dist(self.venv, name="lib")
        (dist / "entry_points.txt").unlink()
        self.assertEqual(pins.entry_points(self.venv, "lib"), {})


if __name__ == "__main__":
    unittest.main()
