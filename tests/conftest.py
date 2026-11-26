"""
Shared test setup. The settings are read at import time (like YAC's specs),
so the environment must be prepared before any `app.*` import.
"""

import base64
import os
import secrets
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _key(kid: str) -> str:
    return f"{kid}:{base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')}"


os.environ.update(
    {
        "YAC_MCP_CONFIG": str(FIXTURES / "config.json"),
        "YAC_MCP_KEYS": f'["{_key("k1")}", "{_key("k0")}"]',
        "YAC_MCP_PUBLIC_URL": "http://localhost:8080",
        "YAC_MCP_ALLOW": '["create", "edit", "delete", "actions"]',
        "YAC_MCP_OIDC_URL": "https://idp.test/.well-known/openid-configuration",
        "YAC_MCP_OIDC_CLIENT_ID": "yac-mcp",
        "YAC_MCP_OIDC_CLIENT_SECRET": "s3cret",
        "YAC_MCP_OIDC_SCOPE": "openid profile email groups offline_access",
    }
)

import pytest  # noqa: E402

from app import consts  # noqa: E402


@pytest.fixture
def env(monkeypatch):
    """Change settings for one test: env(allow=[])."""

    def setter(**kwargs):
        for key, value in kwargs.items():
            monkeypatch.setattr(consts.ENV, key, value)

    return setter
