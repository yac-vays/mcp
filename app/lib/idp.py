"""
The upstream OIDC provider (the one VAYS and YAC use), where this server is
a confidential client: discovery, authorization URL, code exchange, refresh
and id-token validation (signature via the cached JWKS, like YAC).

Raises: [app.model.err.IdPError]
"""

import logging
import time
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet

from app import consts
from app.lib import http
from app.model.err import IdPError

logger = logging.getLogger(__name__)

_CACHE_TTL = 3600
_cache: dict[str, tuple[float, dict]] = {}


async def _get_json(url: str, key: str, force: bool = False) -> dict:
    cached = _cache.get(key)
    if cached and not force and cached[0] > time.time():
        return cached[1]
    try:
        response = await http.client().get(url)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as error:
        raise IdPError(f"The identity provider is not available ({error})") from error
    _cache[key] = (time.time() + _CACHE_TTL, data)
    return data


async def metadata() -> dict:
    if not consts.ENV.oidc_url:
        raise IdPError("No identity provider configured (YAC_MCP_OIDC_URL)")
    return await _get_json(consts.ENV.oidc_url, "metadata")


async def _jwks(force: bool = False) -> KeySet:
    meta = await metadata()
    return KeySet.import_key_set(await _get_json(meta["jwks_uri"], "jwks", force))


def redirect_uri() -> str:
    return f"{consts.ENV.public_url}{consts.CALLBACK_PATH}"


async def authorization_url(state: str, nonce: str, code_challenge: str) -> str:
    meta = await metadata()
    params = {
        "response_type": "code",
        "client_id": consts.ENV.oidc_client_id,
        "redirect_uri": redirect_uri(),
        "scope": consts.ENV.oidc_scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in meta["authorization_endpoint"] else "?"
    return f"{meta['authorization_endpoint']}{sep}{urlencode(params)}"


async def _token_request(data: dict) -> dict:
    meta = await metadata()
    auth = None
    if consts.ENV.oidc_client_auth == "client_secret_basic":
        auth = (consts.ENV.oidc_client_id, consts.ENV.oidc_client_secret)
    else:
        data = {
            **data,
            "client_id": consts.ENV.oidc_client_id,
            "client_secret": consts.ENV.oidc_client_secret,
        }
    try:
        response = await http.client().post(meta["token_endpoint"], data=data, auth=auth)
    except httpx.HTTPError as error:
        raise IdPError(f"The identity provider is not available ({error})") from error
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code >= 400 or "access_token" not in body:
        error = body.get("error_description") or body.get("error") or response.text[:200]
        logger.info(f"Token request rejected by the identity provider: {error}")
        raise IdPError(f"The identity provider rejected the request: {error}")
    return body


async def exchange_code(code: str, code_verifier: str) -> dict:
    return await _token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(),
            "code_verifier": code_verifier,
        }
    )


async def refresh(refresh_token: str) -> dict:
    return await _token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})


async def validate_id_token(id_token: str, nonce: str | None = None) -> dict:
    meta = await metadata()
    algorithms = meta.get("id_token_signing_alg_values_supported") or ["RS256"]
    algorithms = [a for a in algorithms if a != "none"]
    try:
        try:
            token = jwt.decode(id_token, await _jwks(), algorithms=algorithms)
        except InvalidKeyIdError:
            token = jwt.decode(id_token, await _jwks(force=True), algorithms=algorithms)
        claims = token.claims
        jwt.JWTClaimsRegistry(
            leeway=120,
            iss={"essential": True, "value": meta["issuer"]},
            exp={"essential": True},
            sub={"essential": True},
        ).validate(claims)
    except (JoseError, ValueError) as error:
        raise IdPError(f"The id-token is not valid ({error})") from error
    aud = claims.get("aud")
    audiences = {aud} if isinstance(aud, str) else set(aud or [])
    if consts.ENV.oidc_client_id not in audiences:
        raise IdPError("The id-token was issued for another client")
    if nonce is not None and claims.get("nonce") != nonce:
        raise IdPError("The id-token nonce does not match the login")
    return claims
