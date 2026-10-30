#!/usr/bin/env python3
"""Check Composio project API access and 1Password catalog metadata.

Uses the same project-key v3 API as composio-health.yml. No vault tool is
executed, and the connected-account response body is never read or persisted.
Passing does not establish an active vault connection or a completed sync.

Contracts:
https://docs.composio.dev/reference/v3/api-reference/connected-accounts/getConnectedAccounts
https://docs.composio.dev/reference/v3/api-reference/tools/getTools
"""

import json
import os
import sys
import urllib.error
import urllib.request


CONNECTIONS_URL = (
    "https://backend.composio.dev/api/v3/connected_accounts"
    "?toolkit_slugs=_1password&statuses=ACTIVE&limit=1"
)
CATALOG_URL = (
    "https://backend.composio.dev/api/v3/tools"
    "?toolkit_slug=_1password&limit=1&toolkit_versions=latest"
)
REQUEST_TIMEOUT = 20
MAX_CATALOG_BYTES = 2 * 1024 * 1024


class CheckFailure(Exception):
    """A fixed, non-sensitive diagnostic suitable for public Actions logs."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the project-key header to a redirected host.
        return None


def http_failure(label, status):
    if status in (401, 403):
        return CheckFailure(f"{label}: project API key rejected or unauthorized (HTTP {status}).")
    return CheckFailure(f"{label}: unexpected HTTP {status}; response body omitted.")


def request(opener, url, api_key, label, read_catalog=False):
    try:
        req = urllib.request.Request(
            url,
            headers={"x-api-key": api_key, "Accept": "application/json"},
            method="GET",
        )
        with opener.open(req, timeout=REQUEST_TIMEOUT) as response:
            if response.status != 200:
                raise http_failure(label, response.status)
            if not read_catalog:
                # Account objects can include auth state. Do not read them.
                return None
            body = response.read(MAX_CATALOG_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise http_failure(label, status) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        # Exception messages and server responses may contain sensitive material.
        raise CheckFailure(f"{label}: request failed; details omitted.") from None

    if len(body) > MAX_CATALOG_BYTES:
        raise CheckFailure("1Password catalog response exceeded the size limit.")
    try:
        return json.loads(body)
    except (ValueError, UnicodeError):
        raise CheckFailure("1Password catalog returned invalid JSON; body omitted.") from None


def check(opener, api_key):
    request(opener, CONNECTIONS_URL, api_key, "Connected-account API access")
    catalog = request(opener, CATALOG_URL, api_key, "1Password catalog", read_catalog=True)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("items"), list):
        raise CheckFailure("1Password catalog returned an unexpected metadata shape.")
    if not catalog["items"]:
        raise CheckFailure("1Password catalog contains no available tool metadata.")
    for item in catalog["items"]:
        toolkit = item.get("toolkit") if isinstance(item, dict) else None
        slug = item.get("slug") if isinstance(item, dict) else None
        if (
            not isinstance(toolkit, dict)
            or toolkit.get("slug") != "_1password"
            or not isinstance(slug, str)
            or not slug.startswith("_1PASSWORD_")
        ):
            raise CheckFailure("1Password catalog returned unexpected toolkit metadata.")


def main(opener=None, environ=None, stdout=None, stderr=None):
    environ = os.environ if environ is None else environ
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    api_key = environ.get("COMPOSIO_API_KEY", "").strip()
    if not api_key:
        print("::error::COMPOSIO_API_KEY repository secret is not configured.", file=stderr)
        return 1
    opener = urllib.request.build_opener(NoRedirect()) if opener is None else opener
    try:
        check(opener, api_key)
    except CheckFailure as error:
        print(f"::error::{error}", file=stderr)
        return 1
    print(
        "Composio project API access and 1Password catalog metadata checks passed. "
        "Connected-account bodies were not read; vault access and synchronization were not tested.",
        file=stdout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
