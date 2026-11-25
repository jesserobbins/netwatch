import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from netwatch import cli


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, out.getvalue()


class OverviewTests(unittest.TestCase):
    def test_a_bare_invocation_prints_the_overview_and_succeeds(self):
        code, text = run([])
        self.assertEqual(code, 0)
        for word in ("Usage", "The loop", "scan", "check", "preview", "apply",
                     "targets remove", "uvtool", "pipx", "state.db"):
            self.assertIn(word, text, word)

    def test_it_names_every_command_the_parser_accepts(self):
        _, text = run([])
        parser = cli.parser()
        subparsers = next(action for action in parser._actions
                          if getattr(action, "choices", None)
                          and "add" in action.choices)
        for command in subparsers.choices:
            self.assertIn(command, text, command)

    def test_asking_for_help_never_creates_the_database(self):
        db = Path(tempfile.mkdtemp()) / "state.db"
        code, _ = run(["--db", str(db)])
        self.assertEqual(code, 0)
        self.assertFalse(db.exists(), "the overview must not open or create the store")

    def test_the_overview_is_text_even_under_json(self):
        code, text = run(["--json"])
        self.assertEqual(code, 0)
        self.assertIn("Usage", text)
        self.assertFalse(text.lstrip().startswith("{"), text[:40])

    def test_no_command_is_not_an_error_any_more(self):
        args = cli.parser().parse_args([])
        self.assertIsNone(args.command)


if __name__ == "__main__":
    unittest.main()
