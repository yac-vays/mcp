import logging
import sys
from contextlib import asynccontextmanager

from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.routes import build_metadata, create_auth_routes, cors_middleware
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from app import consts
from app.lib import backends
from app.lib import envelope
from app.lib import http
from app.lib import login
from app.lib import plugin
from app.lib import tools
from app.lib.oauth import StatelessProvider, resource_url
from app.version import VERSION

log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(plugin.get_module("format", consts.ENV.format_plugin).formatter)
logging.basicConfig(level=consts.ENV.log_level.upper(), handlers=[log_handler])

logger = logging.getLogger(__name__)


class HealthAccessLogFilter(logging.Filter):
    """Demote successful `GET /health` access-log lines to DEBUG (like YAC)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            _, method, path, _, status_code = record.args  # type: ignore[misc]
        except (TypeError, ValueError):
            return True
        if method != "GET" or path != "/health" or status_code >= 300:
            return True
        record.levelno = logging.DEBUG
        record.levelname = logging.getLevelName(logging.DEBUG)
        return logging.getLogger(record.name).isEnabledFor(logging.DEBUG)


logging.getLogger("uvicorn.access").addFilter(HealthAccessLogFilter())


def _auth_settings() -> AuthSettings:
    return AuthSettings(
        issuer_url=consts.ENV.public_url,  # type: ignore[arg-type]
        resource_server_url=resource_url(),  # type: ignore[arg-type]
        validate_token_resource=True,
    )


def _auth_routes(provider: StatelessProvider) -> list[Route]:
    """
    The SDK's OAuth routes, with the metadata additionally announcing client
    metadata document (CIMD) support.
    """
    registration = ClientRegistrationOptions(enabled=consts.ENV.client_registration)
    routes = [
        r
        for r in create_auth_routes(
            provider=provider,  # type: ignore[arg-type]
            issuer_url=_auth_settings().issuer_url,
            client_registration_options=registration,
            revocation_options=RevocationOptions(enabled=False),
        )
        if r.path != "/.well-known/oauth-authorization-server"
    ]
    metadata = build_metadata(
        _auth_settings().issuer_url,
        None,
        registration,
        RevocationOptions(enabled=False),
    )
    metadata.client_id_metadata_document_supported = consts.ENV.client_metadata_documents
    metadata.token_endpoint_auth_methods_supported = [
        "client_secret_post",
        "client_secret_basic",
        "none",
    ]
    handler = cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"])
    routes.append(
        Route("/.well-known/oauth-authorization-server", handler, methods=["GET", "OPTIONS"])
    )
    return routes


def create_app() -> Starlette:
    backends.config()  # fail early on a broken config file
    plugin.get_modules("renderer")

    provider = StatelessProvider()
    if consts.ENV.dev_token_passthrough:
        logger.warning(
            "DEV MODE: bearer tokens are forwarded unverified to the backends, no OAuth server!"
        )
        mcp = MCPServer("yac", instructions=tools.instructions())
        auth_routes: list[Route] = []
    else:
        envelope.seal("check", {})  # fail early without keys
        mcp = MCPServer(
            "yac",
            instructions=tools.instructions(),
            token_verifier=ProviderTokenVerifier(provider),  # type: ignore[arg-type]
            auth=_auth_settings(),
        )
        auth_routes = [*_auth_routes(provider), *login.routes(provider)]
    tools.register(mcp)
    logger.info(f"Allowed changes: {consts.ENV.allow or 'none (read-only)'}")

    mcp_app = mcp.streamable_http_app(
        streamable_http_path=consts.MCP_PATH,
        stateless_http=True,
        json_response=True,
        # Host/Origin checks are left to the ingress (the public host name is
        # not known here); browsers can't send the bearer token cross-origin.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host="0.0.0.0",
    )

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": VERSION})

    @asynccontextmanager
    async def lifespan(_: Starlette):
        async with mcp.session_manager.run():
            yield
        await http.close()

    return Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            *auth_routes,
            Mount("/", app=mcp_app),
        ],
        lifespan=lifespan,
    )


app = create_app()
