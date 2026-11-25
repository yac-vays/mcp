"""
A thin async client for the YAC REST API, authenticated as the user (the
user's id-token, exactly like VAYS) and marked with the `YAC-Client: mcp`
header.

Raises: [app.model.err.UpstreamError]
"""

import logging
from typing import Any
from urllib.parse import quote

import httpx

from app import consts
from app.lib import http
from app.lib.backends import Backend
from app.model.err import UpstreamError
from app.version import VERSION

logger = logging.getLogger(__name__)

WARNING_HEADERS = ("warning", "yac-warning")

def _q(value: str) -> str:
    return quote(value, safe="")


def _error_message(response: httpx.Response) -> tuple[str, str]:
    try:
        body = response.json()
    except ValueError:
        return response.reason_phrase, response.text[:500]
    if isinstance(body, dict) and "message" in body:
        return str(body.get("title", "")), str(body["message"])
    if isinstance(body, dict) and isinstance(body.get("detail"), list):
        parts = []
        for item in body["detail"]:
            loc = "/".join(str(p) for p in item.get("loc", [])[1:])
            parts.append(f"{loc}: {item.get('msg')}" if loc else str(item.get("msg")))
        return "Invalid request", "; ".join(dict.fromkeys(parts))
    return response.reason_phrase, str(body)[:500]


class Yac:
    def __init__(self, backend: Backend, token: str):
        self.backend = backend
        self.token = token
        self.warnings: list[str] = []

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": f"yac-mcp/{VERSION}",
            **consts.CLIENT_HEADERS,
        }
        try:
            response = await http.client().request(
                method, f"{self.backend.url}{path}", headers=headers, **kwargs
            )
        except httpx.HTTPError as error:
            raise UpstreamError(
                502, "Backend unreachable", f"{self.backend.name}: {error}"
            ) from error
        # `Warning`: stale data (the repo is unreachable); `YAC-Warning`: an
        # action that failed after a committed write.
        for header in WARNING_HEADERS:
            if header in response.headers:
                self.warnings.append(response.headers[header])
        if response.status_code >= 400:
            title, message = _error_message(response)
            if response.status_code == 401:
                message = f"The backend did not accept the login: {message}"
            raise UpstreamError(response.status_code, title, message)
        return response

    async def _json(self, method: str, path: str, **kwargs) -> Any:
        response = await self._request(method, path, **kwargs)
        return response.json() if response.content else None

    async def types(self) -> list[dict]:
        return await self._json("GET", "/entity")

    async def entities(self, type_name: str, search: str, skip: int, limit: int) -> dict:
        params = {"search": search, "skip": skip, "limit": limit}
        return await self._json("GET", f"/entity/{_q(type_name)}", params=params)

    async def entity_yaml(self, type_name: str, name: str) -> str:
        response = await self._request("GET", f"/entity/{_q(type_name)}/{_q(name)}/yaml")
        return response.text

    async def logs(self, type_name: str, name: str) -> list[dict]:
        return await self._json("GET", f"/entity/{_q(type_name)}/{_q(name)}/logs")

    async def log_content(self, type_name: str, name: str, log: str) -> dict:
        path = f"/entity/{_q(type_name)}/{_q(name)}/logs/{_q(log)}/content"
        return await self._json("GET", path)

    async def validate(self, body: dict) -> dict:
        return await self._json("POST", "/validate", json=body)

    async def create(self, type_name: str, body: dict, msg: str, run: list[str]) -> dict:
        params = {"msg": msg, "run": run}
        return await self._json("POST", f"/entity/{_q(type_name)}", json=body, params=params)

    async def replace(
        self, type_name: str, name: str, body: dict, msg: str, run: list[str]
    ) -> dict:
        params = {"msg": msg, "run": run}
        path = f"/entity/{_q(type_name)}/{_q(name)}"
        return await self._json("PUT", path, json=body, params=params)

    async def delete(self, type_name: str, name: str, msg: str, run: list[str]) -> None:
        params = {"msg": msg, "run": run}
        await self._request("DELETE", f"/entity/{_q(type_name)}/{_q(name)}", params=params)

    async def run_action(self, type_name: str, name: str, action: str) -> None:
        path = f"/entity/{_q(type_name)}/{_q(name)}/run/{_q(action)}"
        await self._request("POST", path)
