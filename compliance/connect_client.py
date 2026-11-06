"""Minimal Posit Connect API client.

Only documented endpoints are used:
  GET   /__api__/v1/content                      list content (admin key sees all)
  GET   /__api__/v1/content/{guid}               one content item
  GET   /__api__/v1/content/{guid}/repository    Git source (404 = not Git-backed)
  GET   /__api__/v1/users/{guid}                 owner details / email
  PATCH /__api__/v1/content/{guid}               {"locked": true, "locked_message": "..."}

The API key is only placed in the Authorization header and never logged.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("branch_compliance.connect")


class ConnectAPIError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ConnectAuthError(ConnectAPIError):
    """401/403: the key is wrong, expired, or not an administrator key."""


class ConnectNotFoundError(ConnectAPIError):
    pass


class ConnectClient:
    def __init__(self, server: str, api_key: str, *, timeout: float = 30.0, verify_ssl: bool = True):
        self.base_url = server.rstrip("/") + "/__api__"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({"Authorization": f"Key {api_key}", "Accept": "application/json"})
        # Retry transient failures on reads only; PATCH is never retried blindly.
        retry = Retry(total=3, backoff_factor=1.0, status_forcelist=(502, 503, 504),
                      allowed_methods=frozenset({"GET"}), raise_on_status=False)
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = self.base_url + path
        try:
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise ConnectAPIError(f"{method} {path} failed: {type(exc).__name__}: {exc}") from exc

        if resp.status_code in (401, 403):
            raise ConnectAuthError(
                f"{method} {path} returned {resp.status_code}; check that the API key is valid "
                "and belongs to an administrator", resp.status_code)
        if resp.status_code == 404:
            raise ConnectNotFoundError(f"{method} {path} returned 404", 404)
        if resp.status_code >= 400:
            raise ConnectAPIError(f"{method} {path} returned {resp.status_code}: {_short(resp.text)}",
                                  resp.status_code)
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise ConnectAPIError(f"{method} {path} returned non-JSON content") from exc

    # ----- reads ---------------------------------------------------------

    def list_content(self) -> list[dict]:
        data = self._request("GET", "/v1/content")
        if not isinstance(data, list):
            raise ConnectAPIError("GET /v1/content did not return a list")
        return data

    def get_content(self, guid: str) -> dict:
        return self._request("GET", f"/v1/content/{guid}")

    def get_repository(self, guid: str) -> dict | None:
        """Git source of the item, or None when it is not Git-backed."""
        try:
            return self._request("GET", f"/v1/content/{guid}/repository")
        except ConnectNotFoundError:
            return None

    def get_user(self, guid: str) -> dict:
        return self._request("GET", f"/v1/users/{guid}")

    # ----- writes --------------------------------------------------------

    def set_locked(self, guid: str, locked: bool, message: str | None = None) -> dict:
        body: dict[str, Any] = {"locked": locked}
        if locked and message:
            body["locked_message"] = message
        return self._request("PATCH", f"/v1/content/{guid}", json=body)


def _short(text: str, limit: int = 300) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."
