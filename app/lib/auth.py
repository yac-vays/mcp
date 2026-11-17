"""
The upstream credential for the current MCP request: the user's id-token
from the gateway access token, or (dev mode only) the request's bearer token.

Raises: [app.model.err.InputError]
"""

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import Context

from app import consts
from app.lib.oauth import GatewayAccessToken
from app.model.err import InputError


def upstream_token(ctx: Context) -> str:
    if consts.ENV.dev_token_passthrough:
        request = ctx.request_context.request
        header = request.headers.get("authorization", "") if request is not None else ""
        if not header.lower().startswith("bearer "):
            raise InputError("Dev mode: send the YAC id-token as `Authorization: Bearer ...`")
        return header[7:].strip()
    token = get_access_token()
    if not isinstance(token, GatewayAccessToken):
        raise InputError("Not logged in")
    return token.id_token
