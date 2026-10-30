"""Offline regression tests: no credential or network access is used."""

import importlib.util
import io
import json
from pathlib import Path
import unittest
import urllib.error


SPEC = importlib.util.spec_from_file_location(
    "check_1password_metadata", Path(__file__).with_name("check_1password_metadata.py")
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
SENTINEL = "SYNTHETIC_PRIVATE_VALUE_MUST_NOT_BE_LOGGED"
VALID_CATALOG = {
    "items": [{"slug": "_1PASSWORD_LIST_VAULTS", "toolkit": {"slug": "_1password"}}]
}


class Response:
    def __init__(self, status=200, body=b"", forbid_read=False):
        self.status = status
        self.body = body
        self.forbid_read = forbid_read
        self.read_called = False
        self.closed = False

    def read(self, size=-1):
        self.read_called = True
        if self.forbid_read:
            raise AssertionError("Connected-account payload must remain unread")
        return self.body if size < 0 else self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class UnreadErrorBody(io.BytesIO):
    def read(self, *args):
        raise AssertionError("HTTP error body must remain unread")


class Opener:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if not self.results:
            raise AssertionError("Unexpected request")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class MetadataChecks(unittest.TestCase):
    def run_check(self, opener, key="synthetic-test-key"):
        out, err = io.StringIO(), io.StringIO()
        code = CHECK.main(
            opener=opener,
            environ={"COMPOSIO_API_KEY": key},
            stdout=out,
            stderr=err,
        )
        output = out.getvalue() + err.getvalue()
        self.assertNotIn(SENTINEL, output)
        self.assertNotIn("synthetic-test-key", output)
        return code, output

    def catalog_check(self, body):
        accounts = Response(body=SENTINEL.encode(), forbid_read=True)
        opener = Opener(accounts, Response(body=body))
        result = self.run_check(opener)
        self.assertFalse(accounts.read_called)
        self.assertTrue(accounts.closed)
        return result

    def test_missing_key_makes_no_request(self):
        for key in ("", " \n "):
            with self.subTest(key_present=bool(key)):
                opener = Opener()
                code, output = self.run_check(opener, key)
                self.assertEqual(code, 1)
                self.assertIn("not configured", output)
                self.assertEqual(opener.calls, [])

    def test_success_only_reads_catalog_and_uses_fixed_get_endpoints(self):
        accounts = Response(body=SENTINEL.encode(), forbid_read=True)
        opener = Opener(accounts, Response(body=json.dumps(VALID_CATALOG).encode()))
        code, output = self.run_check(opener)
        self.assertEqual(code, 0)
        self.assertIn("synchronization were not tested", output)
        self.assertFalse(accounts.read_called)
        self.assertTrue(accounts.closed)
        self.assertEqual([r.full_url for r, _ in opener.calls], [CHECK.CONNECTIONS_URL, CHECK.CATALOG_URL])
        for req, timeout in opener.calls:
            self.assertEqual(req.get_method(), "GET")
            self.assertIsNone(req.data)
            self.assertEqual(req.get_header("X-api-key"), "synthetic-test-key")
            self.assertEqual(timeout, 20)

    def test_auth_and_server_http_errors_do_not_read_or_print_bodies(self):
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status):
                body = UnreadErrorBody(SENTINEL.encode())
                error = urllib.error.HTTPError(CHECK.CONNECTIONS_URL, status, SENTINEL, {}, body)
                opener = Opener(error)
                code, output = self.run_check(opener)
                self.assertEqual(code, 1)
                self.assertIn(str(status), output)
                self.assertTrue(body.closed)
                self.assertEqual(len(opener.calls), 1)

    def test_catalog_http_error_fails_without_success_summary(self):
        error = urllib.error.HTTPError(
            CHECK.CATALOG_URL, 403, SENTINEL, {}, UnreadErrorBody(SENTINEL.encode())
        )
        code, output = self.run_check(Opener(Response(forbid_read=True), error))
        self.assertEqual(code, 1)
        self.assertNotIn("checks passed", output)

    def test_network_failures_are_redacted(self):
        for error in (urllib.error.URLError(SENTINEL), TimeoutError(SENTINEL), OSError(SENTINEL)):
            with self.subTest(error_type=type(error).__name__):
                code, output = self.run_check(Opener(error))
                self.assertEqual(code, 1)
                self.assertIn("request failed", output)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(
            CHECK.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid/")
        )
        response = Response(status=302, forbid_read=True)
        code, output = self.run_check(Opener(response))
        self.assertEqual(code, 1)
        self.assertFalse(response.read_called)
        self.assertIn("302", output)

    def test_malformed_catalog_is_redacted(self):
        code, output = self.catalog_check(SENTINEL.encode())
        self.assertEqual(code, 1)
        self.assertIn("invalid JSON", output)

    def test_empty_or_wrong_catalog_shapes_fail(self):
        for value in ({"items": []}, {"items": {}}, [], {"unrecognized": SENTINEL}):
            with self.subTest(shape=type(value).__name__):
                code, _ = self.catalog_check(json.dumps(value).encode())
                self.assertEqual(code, 1)

    def test_wrong_toolkit_and_non_object_items_fail(self):
        for item in (None, "unexpected", {"slug": "GMAIL_SEND_EMAIL", "toolkit": {"slug": "gmail"}}):
            with self.subTest(item_type=type(item).__name__):
                code, _ = self.catalog_check(json.dumps({"items": [item]}).encode())
                self.assertEqual(code, 1)

    def test_oversized_catalog_is_rejected(self):
        code, output = self.catalog_check(b" " * (CHECK.MAX_CATALOG_BYTES + 1))
        self.assertEqual(code, 1)
        self.assertIn("size limit", output)


if __name__ == "__main__":
    unittest.main()
