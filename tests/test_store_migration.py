import sqlite3
import tempfile
import unittest
from pathlib import Path

from netwatch import store as store_module


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _v10(self, name="old.db"):
        path = self.tmp / name
        con = sqlite3.connect(path)
        con.executescript("""
            CREATE TABLE targets(name TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE scans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, body TEXT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, kind TEXT, body TEXT);
            CREATE TABLE cache(key TEXT PRIMARY KEY, at INTEGER, body TEXT);
            CREATE TABLE plans(id INTEGER PRIMARY KEY, target TEXT, at INTEGER, status TEXT, body TEXT, result TEXT);
            INSERT INTO targets VALUES('arch', '{"name":"arch","kind":"arch","path":"/"}');
            PRAGMA user_version=10;
        """)
        con.commit()
        con.close()
        path.chmod(0o600)
        return path

    def test_version_10_database_upgrades_in_place(self):
        store = store_module.Store(self._v10())
        row = store.db.execute(
            "SELECT name, kind, state, removed, generation, state_seq FROM targets").fetchone()
        self.assertEqual(tuple(row), ("arch", "arch", "live", 0, 1, 0))
        self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 11)
        store.close()

    def test_version_12_database_is_refused_not_stamped_down(self):
        path = self.tmp / "future.db"
        con = sqlite3.connect(path)
        con.execute("PRAGMA user_version=12")
        con.commit()
        con.close()
        path.chmod(0o600)
        with self.assertRaises(store_module.Error):
            store_module.Store(path)

    def test_new_empty_database_initializes_at_11(self):
        store = store_module.Store(self.tmp / "new.db")
        self.assertEqual(store.schema_version, 11)
        store.close()

    def test_migration_is_idempotent_across_reopens(self):
        path = self._v10("x.db")
        store_module.Store(path).close()
        second = store_module.Store(path)
        self.assertEqual(second.schema_version, 11)
        self.assertEqual(
            second.db.execute("SELECT count(*) FROM targets WHERE state='live'").fetchone()[0], 1)
        second.close()

    def test_scan_tables_exist_after_migration(self):
        store = store_module.Store(self._v10())
        names = {r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("scan_runs", names)
        self.assertIn("scan_records", names)
        store.close()

    def test_busy_timeout_is_raised_for_every_connection(self):
        store = store_module.Store(self.tmp / "busy.db")
        self.assertEqual(store.db.execute("PRAGMA busy_timeout").fetchone()[0], 60000)
        store.close()


class AddTargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = store_module.Store(self.tmp / "t.db")

    def tearDown(self):
        self.store.close()

    def test_add_target_writes_named_columns_with_defaults(self):
        self.store.add_target("arch", {"name": "arch", "kind": "arch"})
        row = self.store.db.execute(
            "SELECT kind, state, removed, generation, state_seq FROM targets").fetchone()
        self.assertEqual(tuple(row), ("arch", "live", 0, 1, 0))

    def test_add_target_reflects_a_removed_revival(self):
        self.store.add_target("arch", {"name": "arch", "kind": "arch"})
        self.store.remove_target("arch")
        self.assertEqual(self.store.db.execute("SELECT removed FROM targets").fetchone()[0], 1)
        self.store.add_target("arch", {"name": "arch", "kind": "arch"})
        row = self.store.db.execute(
            "SELECT removed, generation, state FROM targets").fetchone()
        # Remove and revive each bump the generation, so every plan approved before
        # either event is refused as stale.
        self.assertEqual(tuple(row), (0, 3, "live"))
        self.assertEqual(self.store.db.execute("SELECT removed FROM targets").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
