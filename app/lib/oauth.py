"""
A stateless OAuth 2.1 authorization server for MCP clients that proxies the
login to the upstream OIDC provider (see `app/lib/login.py` for the consent
page and the IdP callback). Implements the MCP SDK's
`OAuthAuthorizationServerProvider`; the SDK's routes do the protocol checks
(PKCE, redirect URI, expiry), this module only seals and opens envelopes:

- registered clients: the `client_id` *is* the sealed client metadata,
  clients with a metadata document (CIMD) use their document URL,
- authorization codes wrap the (not yet redeemed) IdP code; the IdP enforces
  single use when the code is exchanged at `/token`,
- access tokens wrap the user's IdP id-token (forwarded to YAC like VAYS
  does) and expire with it, refresh tokens wrap the IdP refresh token.

Raises: [mcp.server.auth.provider.AuthorizeError, ...TokenError, ...RegistrationError]
"""

import asyncio
import ipaddress
import json
import logging
import socket
import time
from urllib.parse import urlencode, urlparse

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl, ValidationError

from app import consts
from app.lib import envelope
from app.lib import http
from app.lib import idp
from app.model.err import EnvelopeError, IdPError

logger = logging.getLogger(__name__)

MAX_CLIENT_ID_LENGTH = 4096
CIMD_MAX_BYTES = 16384
CIMD_CACHE_TTL = 300
_LOOPBACK = ("localhost", "127.0.0.1", "[::1]", "::1")


def resource_url() -> str:
    return f"{consts.ENV.public_url}{consts.MCP_PATH}"


class GatewayClient(OAuthClientInformationFull):
    """
    Scopes are not used by this server (all access is decided by YAC), so any
    requested scope is accepted. Loopback redirect URIs may use any port
    (RFC 8252, section 7.3), as native clients pick a free port at runtime.
    """

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        return None if requested_scope is None else requested_scope.split()

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        try:
            return super().validate_redirect_uri(redirect_uri)
        except InvalidRedirectUriError:
            if redirect_uri is None or redirect_uri.host not in _LOOPBACK:
                raise
            for registered in self.redirect_uris or []:
                if (
                    registered.host == redirect_uri.host
                    and registered.scheme == redirect_uri.scheme
                    and registered.path == redirect_uri.path
                    and registered.query == redirect_uri.query
                ):
                    return redirect_uri
            raise


class GatewayAuthorizationCode(AuthorizationCode):
    idp_code: str
    idp_verifier: str
    nonce: str


class GatewayRefreshToken(RefreshToken):
    idp_refresh_token: str
    session_exp: int


class GatewayAccessToken(AccessToken):
    id_token: str


_cimd_cache: dict[str, tuple[float, GatewayClient]] = {}


async def _check_public_host(host: str) -> None:
    if consts.ENV.client_metadata_allow_private:
        return
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ValueError(f"cannot resolve {host}") from error
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global:
            raise ValueError(f"{host} resolves to a non-public address")


async def _client_from_metadata_document(url: str) -> GatewayClient | None:
    cached = _cimd_cache.get(url)
    if cached and cached[0] > time.time():
        return cached[1]
    parsed = urlparse(url)
    try:
        if parsed.scheme != "https" or not parsed.hostname or parsed.path in ("", "/"):
            raise ValueError("client metadata document URLs must be https URLs with a path")
        await _check_public_host(parsed.hostname)
        async with http.client().stream(
            "GET", url, follow_redirects=False, timeout=5, headers={"Accept": "application/json"}
        ) as response:
            response.raise_for_status()
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > CIMD_MAX_BYTES:
                    raise ValueError("client metadata document too large")
        document = json.loads(body)
        if not isinstance(document, dict) or document.get("client_id") != url:
            raise ValueError("the document's client_id does not match its URL")
        if document.get("token_endpoint_auth_method", "none") != "none":
            raise ValueError("only public clients (token_endpoint_auth_method none) are supported")
        document.pop("client_secret", None)
        client = GatewayClient.model_validate({**document, "token_endpoint_auth_method": "none"})
    except (httpx.HTTPError, ValueError, ValidationError) as error:
        logger.warning(f"Rejected client metadata document {url}: {error}")
        return None
    _cimd_cache[url] = (time.time() + CIMD_CACHE_TTL, client)
    return client


def _redirect(base: str, **params: str | None) -> str:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    return f"{base}{'&' if '?' in base else '?'}{query}"


class StatelessProvider:
    """`OAuthAuthorizationServerProvider` without any server-side state."""

    # Clients

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id.startswith("https://"):
            if not consts.ENV.client_metadata_documents:
                return None
            return await _client_from_metadata_document(client_id)
        if client_id.count(".") != 4:
            return None
        try:
            data = envelope.open_("client", client_id)
        except EnvelopeError:
            return None
        metadata = {k: v for k, v in data.items() if k not in ("typ", "iss", "exp")}
        return GatewayClient.model_validate({**metadata, "client_id": client_id})

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # The SDK's registration handler returns this very object to the
        # client, so the client_id it generated is replaced by the sealed
        # metadata (tests/test_oauth.py pins this behavior).
        metadata = client_info.model_dump(
            mode="json", exclude={"client_id", "client_id_issued_at"}, exclude_none=True
        )
        client_id = envelope.seal("client", metadata)
        if len(client_id) > MAX_CLIENT_ID_LENGTH:
            raise RegistrationError("invalid_client_metadata", "client metadata too large")
        client_info.client_id = client_id

    # Authorization

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource and params.resource.rstrip("/") not in (
            resource_url(),
            consts.ENV.public_url,
        ):
            raise AuthorizeError("invalid_target", f"unknown resource {params.resource}")
        authz = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "state": params.state,
            "code_challenge": params.code_challenge,
            "scopes": params.scopes or [],
        }
        request = envelope.seal("authz", authz, ttl=consts.ENV.login_ttl)
        return _redirect(f"{consts.ENV.public_url}{consts.CONSENT_PATH}", request=request)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> GatewayAuthorizationCode | None:
        try:
            data = envelope.open_("code", authorization_code)
        except EnvelopeError:
            return None
        authz = data["authz"]
        if authz["client_id"] != client.client_id:
            return None
        return GatewayAuthorizationCode(
            code=authorization_code,
            scopes=authz["scopes"],
            expires_at=data["exp"],
            client_id=authz["client_id"],
            code_challenge=authz["code_challenge"],
            redirect_uri=AnyUrl(authz["redirect_uri"]),
            redirect_uri_provided_explicitly=authz["redirect_uri_provided_explicitly"],
            resource=resource_url(),
            idp_code=data["idp_code"],
            idp_verifier=data["verifier"],
            nonce=data["nonce"],
        )

    async def exchange_authorization_code(  # pylint: disable=unused-argument
        self, client: OAuthClientInformationFull, authorization_code: GatewayAuthorizationCode
    ) -> OAuthToken:
        try:
            tokens = await idp.exchange_code(
                authorization_code.idp_code, authorization_code.idp_verifier
            )
            if "id_token" not in tokens:
                raise IdPError("The identity provider returned no id-token")
            claims = await idp.validate_id_token(tokens["id_token"], authorization_code.nonce)
        except IdPError as error:
            raise TokenError("invalid_grant", str(error)) from error
        return self._issue(
            client_id=authorization_code.client_id,
            claims=claims,
            id_token=tokens["id_token"],
            idp_refresh_token=tokens.get("refresh_token"),
            scopes=authorization_code.scopes,
            session_exp=int(time.time()) + consts.ENV.session_max_age,
        )

    # Tokens

    def _issue(self, *, client_id, claims, id_token, idp_refresh_token, scopes, session_exp):
        exp = int(claims["exp"])
        access = envelope.seal(
            "access",
            {"client_id": client_id, "sub": claims["sub"], "id_token": id_token, "scopes": scopes},
            exp=exp,
        )
        refresh = None
        if idp_refresh_token:
            refresh = envelope.seal(
                "refresh",
                {
                    "client_id": client_id,
                    "sub": claims["sub"],
                    "rt": idp_refresh_token,
                    "scopes": scopes,
                    "session_exp": session_exp,
                },
                exp=session_exp,
            )
        return OAuthToken(
            access_token=access,
            expires_in=max(exp - int(time.time()), 1),
            scope=" ".join(scopes) or None,
            refresh_token=refresh,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> GatewayRefreshToken | None:
        try:
            data = envelope.open_("refresh", refresh_token)
        except EnvelopeError:
            return None
        if data["client_id"] != client.client_id:
            return None
        return GatewayRefreshToken(
            token=refresh_token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["exp"],
            resource=resource_url(),
            subject=data["sub"],
            idp_refresh_token=data["rt"],
            session_exp=data["session_exp"],
        )

    async def exchange_refresh_token(  # pylint: disable=unused-argument
        self,
        client: OAuthClientInformationFull,
        refresh_token: GatewayRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        try:
            tokens = await idp.refresh(refresh_token.idp_refresh_token)
            if "id_token" not in tokens:
                raise IdPError(
                    "The identity provider returned no new id-token on refresh, please log in again"
                )
            claims = await idp.validate_id_token(tokens["id_token"])
        except IdPError as error:
            raise TokenError("invalid_grant", str(error)) from error
        if claims["sub"] != refresh_token.subject:
            raise TokenError("invalid_grant", "The refreshed login belongs to another user")
        return self._issue(
            client_id=refresh_token.client_id,
            claims=claims,
            id_token=tokens["id_token"],
            idp_refresh_token=tokens.get("refresh_token") or refresh_token.idp_refresh_token,
            scopes=scopes or refresh_token.scopes,
            session_exp=refresh_token.session_exp,
        )

    async def load_access_token(self, token: str) -> GatewayAccessToken | None:
        try:
            data = envelope.open_("access", token)
        except EnvelopeError:
            return None
        return GatewayAccessToken(
            token=token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=data["exp"],
            resource=resource_url(),
            subject=data["sub"],
            id_token=data["id_token"],
        )

    async def revoke_token(self, token) -> None:
        """Stateless: tokens expire with the id-token, sessions at the IdP."""

    async def exchange_identity_assertion(self, client, params) -> OAuthToken:
        raise TokenError("unsupported_grant_type", "not supported")
