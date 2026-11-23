"""The batched OSV helper: one or two requests screen a whole scan, in input order."""
import unittest
from unittest.mock import patch

from netwatch import sources
from netwatch.core import Error


def query(name):
    return {"package": {"name": name, "ecosystem": "PyPI"}, "version": "1"}


class OsvBatchTests(unittest.TestCase):
    def test_ids_come_back_in_input_order(self):
        calls = []
        def request(url, body=None):
            calls.append((url, body))
            return {"results": [{"vulns": [{"id": "GHSA-b"}]}, {}, {"vulns": [{"id": "GHSA-c"}]}]}
        queries = [query("a"), query("b"), query("c")]
        self.assertEqual(sources.osv_batch(queries, request=request),
                         [["GHSA-b"], [], ["GHSA-c"]])
        self.assertEqual(calls[0][0], sources.OSV_BATCH)

    def test_it_chunks_at_the_documented_cap(self):
        sizes = []
        def request(url, body=None):
            sizes.append(len(body["queries"]))
            return {"results": [{} for _ in body["queries"]]}
        sources.osv_batch([query("p%d" % i) for i in range(1500)], request=request)
        self.assertEqual(sizes, [1000, 500])

    def test_a_refused_batch_is_retried_with_a_smaller_chunk(self):
        sizes = []
        def request(url, body=None):
            sizes.append(len(body["queries"]))
            if len(body["queries"]) > 400:
                raise Error("OSV refused the batch: too many queries")
            return {"results": [{} for _ in body["queries"]]}
        ids = sources.osv_batch([query("p%d" % i) for i in range(500)], request=request)
        self.assertEqual(len(ids), 500)
        self.assertGreater(len(sizes), 2)

    def test_a_paged_result_is_followed(self):
        def request(url, body=None):
            queries = body["queries"]
            if any("page_token" in q for q in queries):
                return {"results": [{"vulns": [{"id": "OSV-2"}]} for q in queries]}
            return {"results": [{"vulns": [{"id": "OSV-1"}], "next_page_token": "t"} for q in queries]}
        ids = sources.osv_batch([query("a")], request=request)
        self.assertEqual(ids, [["OSV-1", "OSV-2"]])

    def test_requests_identify_netwatch(self):
        # What actually goes on the wire: capture the Request fetch builds for a batch call.
        with patch.object(sources.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = Error("captured request")
            with self.assertRaises(Error):
                sources.fetch(sources.OSV_BATCH, {})
            request = build.return_value.open.call_args[0][0]
        self.assertTrue(request.get_header("User-agent").startswith("netwatch/"),
                        request.get_header("User-agent"))

    def test_the_user_agent_names_netwatch(self):
        self.assertTrue(sources.user_agent().startswith("netwatch/"), sources.user_agent())
