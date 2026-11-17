"""
Stateless state: everything the server would otherwise store (login state,
authorization codes, tokens, registered clients, consents) is sealed into an
encrypted, authenticated envelope (JWE compact, `dir` + `A256GCM`, deflated)
and handed to the client. Only the keys are shared between replicas.

Every envelope carries its type (`typ`), the issuer (`iss`) and an expiry
(`exp`, optional), so an envelope of one type is never accepted as another.

Raises: [app.model.err.EnvelopeError, app.model.err.ConfigError]
"""

import base64
import binascii
import json
import secrets
import time
from functools import lru_cache
from typing import Any

from joserfc import jwe
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, OctKey

from app import consts
from app.model.err import ConfigError, EnvelopeError

_ALG = {"alg": "dir", "enc": "A256GCM", "zip": "DEF"}


def _decode_key(spec: str) -> tuple[str, bytes]:
    kid, sep, value = spec.partition(":")
    if not sep or not kid:
        raise ConfigError('YAC_MCP_KEYS entries must look like "kid:base64url-key"')
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as error:
        raise ConfigError(f"YAC_MCP_KEYS key {kid} is not base64url") from error
    if len(raw) != 32:
        raise ConfigError(f"YAC_MCP_KEYS key {kid} must be 32 bytes")
    return kid, raw


@lru_cache(maxsize=1)
def _keys() -> tuple[str, KeySet]:
    if not consts.ENV.keys:
        raise ConfigError("No envelope keys configured (YAC_MCP_KEYS)")
    decoded = [_decode_key(spec) for spec in consts.ENV.keys]
    keyset = KeySet([OctKey.import_key(raw, {"kid": kid}) for kid, raw in decoded])
    return decoded[0][0], keyset


def generate_key() -> str:
    """A new key spec for YAC_MCP_KEYS (also: `python -m app.lib.envelope`)."""
    raw = secrets.token_bytes(32)
    kid = secrets.token_hex(4)
    return f"{kid}:{base64.urlsafe_b64encode(raw).decode().rstrip('=')}"


def seal(typ: str, data: dict, ttl: int | None = None, exp: int | None = None) -> str:
    kid, keyset = _keys()
    claims: dict[str, Any] = {"typ": typ, "iss": consts.ENV.public_url, **data}
    if ttl is not None:
        exp = int(time.time()) + ttl
    if exp is not None:
        claims["exp"] = int(exp)
    plaintext = json.dumps(claims, separators=(",", ":")).encode()
    return jwe.encrypt_compact({**_ALG, "kid": kid}, plaintext, keyset.get_by_kid(kid))


def open_(typ: str, value: str) -> dict:
    _, keyset = _keys()
    try:
        plaintext = jwe.decrypt_compact(value, keyset).plaintext
        claims = json.loads(plaintext or b"")
    except (JoseError, ValueError, TypeError) as error:
        raise EnvelopeError(f"invalid or unknown {typ}") from error
    if not isinstance(claims, dict) or claims.get("typ") != typ:
        raise EnvelopeError(f"invalid or unknown {typ}")
    if claims.get("iss") != consts.ENV.public_url:
        raise EnvelopeError(f"{typ} was issued for another server")
    if "exp" in claims and claims["exp"] < time.time():
        raise EnvelopeError(f"{typ} has expired")
    return claims


if __name__ == "__main__":
    print(generate_key())
