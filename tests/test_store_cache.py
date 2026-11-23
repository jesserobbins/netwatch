import tempfile
import unittest
from pathlib import Path

from netwatch import store as store_module


class CachedManyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.path = self.root / "state.db"

    def test_it_returns_only_fresh_hits(self):
        store = store_module.Store(self.path)
        store.cached_put("k1", {"v": 1}); store.cached_put("k2", {"v": 2})
        self.assertEqual(store.cached_many(["k1", "k2", "missing"]), {"k1": {"v": 1}, "k2": {"v": 2}})
        self.assertEqual(store.cached_many(["k1"], max_age=0), {})
        store.close()

    def test_a_long_key_list_does_not_break_the_query(self):
        store = store_module.Store(self.path)
        keys = ["k%d" % i for i in range(1200)]
        for key in keys[:3]:
            store.cached_put(key, {"v": key})
        self.assertEqual(sorted(store.cached_many(keys)), ["k0", "k1", "k2"])
        store.close()
