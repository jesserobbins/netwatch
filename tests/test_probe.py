import os
import tempfile
import time
import unittest
from pathlib import Path

from netwatch import probe


def make_venv(root: Path):
    venv = root / "v"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("")
    return venv


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def test_an_absent_probe_is_absent(self):
        self.assertEqual(probe.read(self.venv), ("absent", None))

    def test_a_published_probe_is_usable(self):
        status, token = probe.publish(self.venv)
        self.assertEqual(status, "published")
        self.assertEqual(probe.read(self.venv), ("usable", token))

    def test_a_zero_length_probe_is_malformed(self):
        (self.venv / probe.NAME).write_text("")
        self.assertEqual(probe.read(self.venv)[0], "malformed")

    def test_a_probe_with_a_non_uuid_is_malformed(self):
        (self.venv / probe.NAME).write_text("netwatch-probe: not-a-uuid\n")
        self.assertEqual(probe.read(self.venv)[0], "malformed")


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def test_publishing_twice_keeps_the_first_token(self):
        _, first = probe.publish(self.venv)
        status, second = probe.publish(self.venv)
        self.assertEqual(status, "present")
        self.assertEqual(first, second)

    def test_publishing_leaves_no_temp_file(self):
        probe.publish(self.venv)
        self.assertEqual([p.name for p in self.venv.iterdir() if ".tmp-" in p.name], [])

    def test_a_second_writer_that_loses_the_race_adopts_the_winners_token(self):
        # Simulate the race: the temp exists and the link target appears first.
        status, token = probe.publish(self.venv)
        loser = probe.publish(self.venv)
        self.assertEqual(loser, ("present", token))
        self.assertEqual([p.name for p in self.venv.iterdir() if ".tmp-" in p.name], [])

    def test_a_read_only_venv_reports_a_write_failure(self):
        probe.cleanup(self.venv)
        os.chmod(self.venv, 0o500)
        try:
            status, _ = probe.publish(self.venv)
        finally:
            os.chmod(self.venv, 0o700)
        self.assertEqual(status, "failed")


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def test_a_stale_temp_is_removed_and_a_fresh_one_kept(self):
        stale = self.venv / (probe.TEMP_PREFIX + "a" * 32)
        stale.write_text("")
        os.utime(stale, (time.time() - 7200,) * 2)
        fresh = self.venv / (probe.TEMP_PREFIX + "b" * 32)
        fresh.write_text("")
        self.assertEqual(probe.cleanup(self.venv), 1)
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())

    def test_a_loosely_named_file_is_never_touched(self):
        loose = self.venv / (probe.TEMP_PREFIX + "nothex")
        loose.write_text("")
        os.utime(loose, (time.time() - 7200,) * 2)
        probe.cleanup(self.venv)
        self.assertTrue(loose.exists())

    def test_a_published_probe_is_never_cleanup_target(self):
        _, token = probe.publish(self.venv)
        os.utime(self.venv / probe.NAME, (time.time() - 7200,) * 2)
        probe.cleanup(self.venv)
        self.assertEqual(probe.read(self.venv), ("usable", token))


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.venv = make_venv(self.root)

    def test_a_token_witness_is_the_token(self):
        _, token = probe.publish(self.venv)
        self.assertEqual(probe.witness(self.venv), {"kind": "token", "value": token})

    def test_two_inode_witnesses_of_an_untouched_venv_are_equal(self):
        before, after = probe.witness(self.venv), probe.witness(self.venv)
        self.assertEqual(before["kind"], "inodes")
        self.assertEqual(before, after)

    def test_a_vanished_probe_does_not_fall_back_to_inodes(self):
        """A token readable earlier and gone later is a change, not an invitation."""
        before = probe.witness(self.venv)      # no token yet: inode witness
        probe.publish(self.venv)
        after = probe.witness(self.venv)       # token appeared
        self.assertNotEqual(before["kind"], after["kind"])


if __name__ == "__main__":
    unittest.main()
