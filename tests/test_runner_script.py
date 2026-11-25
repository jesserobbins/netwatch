import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "netwatch-run.sh"


class RunnerScriptTests(unittest.TestCase):
    """Guards for the bootstrap script. The install path itself is exercised by hand."""

    def test_the_script_is_present_and_executable(self):
        self.assertTrue(SCRIPT.is_file(), SCRIPT)
        self.assertTrue(os.access(SCRIPT, os.X_OK), "netwatch-run.sh must be executable")

    def test_it_parses_cleanly(self):
        result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_it_refuses_a_missing_interpreter_with_a_clear_message(self):
        env = {**os.environ, "NETWATCH_PYTHON": "definitely-not-a-python",
               "NETWATCH_VENV": str(Path(tempfile.mkdtemp()) / "venv")}
        result = subprocess.run([str(SCRIPT)], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 127)
        self.assertIn("NETWATCH_PYTHON", result.stderr)


if __name__ == "__main__":
    unittest.main()
