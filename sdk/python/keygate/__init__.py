"""Клиент keygate на стандартной библиотеке Python."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

__version__ = "0.1.0"


class KeyGateError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"keygate: HTTP {status}: {body}")
        self.status = status
        self.body = body


class KeyGateClient:
    def __init__(
        self,
        base_url: str | None = None,
        master_key: str | None = None,
        client_id: str = "python-sdk",
    ) -> None:
        self.base_url = (base_url or os.environ.get("KEYGATE_URL", "http://127.0.0.1:8080")).rstrip("/")
        self.master_key = master_key or os.environ.get("KEYGATE_MASTER_KEY", "kg_master_local")
        self.client_id = client_id

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "X-KeyGate-Key": self.master_key,
                "X-Client-ID": self.client_id,
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=10) as response:
                raw = response.read().decode()
        except HTTPError as error:
            raise KeyGateError(error.code, error.read().decode()) from error
        return json.loads(raw) if raw else None

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/healthz")

    def resolve(self, provider: str, scope: str = "read", ttl: int = 60) -> dict[str, Any]:
        return self._request("POST", "/v1/keys/resolve", {"provider": provider, "scope": scope, "ttl": ttl})

    def rotate(self, provider: str) -> dict[str, Any]:
        return self._request("POST", "/v1/keys/rotate", {"provider": provider})

    def audit(self) -> dict[str, Any]:
        return self._request("GET", "/v1/audit")

    def providers(self) -> dict[str, Any]:
        return self._request("GET", "/v1/providers")

    def metrics(self) -> dict[str, Any]:
        return self._request("GET", "/v1/metrics")


__all__ = ["KeyGateClient", "KeyGateError", "__version__"]
