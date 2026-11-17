"""
The shared outgoing HTTP client (connection pooling), closed on shutdown.
"""

import httpx

from app import consts

_CLIENT: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    global _CLIENT  # pylint: disable=global-statement
    if _CLIENT is None:
        _CLIENT = httpx.AsyncClient(timeout=consts.ENV.upstream_timeout)
    return _CLIENT


async def close() -> None:
    global _CLIENT  # pylint: disable=global-statement
    if _CLIENT is not None:
        await _CLIENT.aclose()
        _CLIENT = None
