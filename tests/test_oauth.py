"""
End to end through the ASGI app: client registration, consent, the (fake)
upstream IdP, the token endpoint, MCP calls with the issued token (the
backend must receive the user's id-token) and refresh.
"""

import base64
import contextlib
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from app.lib import envelope
from app.lib import idp
from app.lib import oauth
from app.main import create_app

from tests.fake_yac import FakeYac

IDP = "https://idp.test"
BASE = "http://localhost:8080"
REDIRECT = "http://127.0.0.1:33418/callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}


class FakeIdP:
    def __init__(self):
        self.key = RSAKey.generate_key(2048, {"kid": "idp1"})
        self.codes: dict[str, str] = {}  # code -> nonce
        self.refresh_tokens: set[str] = set()
        self.refresh_returns_id_token = True
        self.token_requests: list[dict] = []

    def id_token(self, nonce=None, sub="alice-sub", aud="yac-mcp", exp_in=300):
        claims = {"iss": IDP, "aud": aud, "sub": sub, "exp": int(time.time()) + exp_in,
                  "iat": int(time.time()), "preferred_username": "alice"}
        if nonce:
            claims["nonce"] = nonce
        return jwt.encode({"alg": "RS256", "kid": "idp1"}, claims, self.key)

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": IDP, "authorization_endpoint": f"{IDP}/authorize",
                "token_endpoint": f"{IDP}/token", "jwks_uri": f"{IDP}/jwks",
                "id_token_signing_alg_values_supported": ["RS256"]})
        if request.url.path == "/jwks":
            return httpx.Response(200, json=KeySet([self.key]).as_dict(private=False))
        if request.url.path == "/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append({**form, "auth": request.headers.get("authorization")})
            if form["grant_type"] == "authorization_code":
                nonce = self.codes.pop(form["code"], None)  # single use
                if nonce is None:
                    return httpx.Response(400, json={"error": "invalid_grant"})
            elif form["refresh_token"] not in self.refresh_tokens:
                return httpx.Response(400, json={"error": "invalid_grant"})
            else:
                nonce = None
                self.refresh_tokens.discard(form["refresh_token"])  # rotation
            refresh = secrets.token_urlsafe(16)
            self.refresh_tokens.add(refresh)
            body = {"access_token": "idp-at", "token_type": "Bearer", "refresh_token": refresh}
            if form["grant_type"] == "authorization_code" or self.refresh_returns_id_token:
                body["id_token"] = self.id_token(nonce)
            return httpx.Response(200, json=body)
        return httpx.Response(404)


@contextlib.asynccontextmanager
async def running():
    """The app with a fake IdP and backend (not a fixture: the MCP lifespan's
    task group must be entered and left in the same task)."""
    idp._cache.clear()  # pylint: disable=protected-access
    fake_idp = FakeIdP()
    with respx.mock(assert_all_called=False) as router:
        router.route(host="idp.test").mock(side_effect=fake_idp.handle)
        yac = FakeYac({"web01": "owner: alice\n"}).mock(router)
        app = create_app()
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url=BASE) as client:
                yield client, fake_idp, yac


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.decode().rstrip("=")


async def _login(client, fake_idp, client_id, redirect=REDIRECT, remember=True):
    verifier, challenge = _pkce()
    r = await client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz",
        "resource": f"{BASE}/mcp"})
    assert r.status_code == 302, r.text
    consent_url = r.headers["location"]
    assert consent_url.startswith(f"{BASE}/consent?request=")
    r = await client.get(consent_url)
    if r.status_code == 200:  # consent page (not remembered yet)
        assert "Allow access to YAC?" in r.text
        request = parse_qs(urlparse(consent_url).query)["request"][0]
        csrf = r.text.split('name="csrf" value="')[1].split('"')[0]
        form = {"request": request, "csrf": csrf, "decision": "allow"}
        if remember:
            form["remember"] = "1"
        r = await client.post("/consent", data=form)
    assert r.status_code == 302
    idp_url = urlparse(r.headers["location"])
    assert f"{idp_url.scheme}://{idp_url.netloc}{idp_url.path}" == f"{IDP}/authorize"
    params = {k: v[0] for k, v in parse_qs(idp_url.query).items()}
    assert params["client_id"] == "yac-mcp" and params["code_challenge_method"] == "S256"
    assert params["redirect_uri"] == f"{BASE}/callback"
    fake_idp.codes["idp-code-1"] = params["nonce"]
    r = await client.get("/callback", params={"code": "idp-code-1", "state": params["state"]})
    assert r.status_code == 302
    back = urlparse(r.headers["location"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == redirect
    query = {k: v[0] for k, v in parse_qs(back.query).items()}
    assert query["state"] == "xyz"
    return query["code"], verifier


async def _register(client):
    r = await client.post("/register", json={
        "redirect_uris": [REDIRECT], "client_name": "Test Agent",
        "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"]})
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


async def _mcp(client, token, method, params=None):
    r = await client.post("/mcp", headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
                          json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    return r


async def test_metadata():
    async with running() as (client, _, _):
        meta = (await client.get("/.well-known/oauth-authorization-server")).json()
        assert meta["issuer"] == BASE and meta["registration_endpoint"] == f"{BASE}/register"
        assert meta["client_id_metadata_document_supported"] is True
        assert "none" in meta["token_endpoint_auth_methods_supported"]
        prm = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
        assert prm["resource"] == f"{BASE}/mcp" and prm["authorization_servers"] == [BASE]
        r = await client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 401 and "oauth-protected-resource" in r.headers["www-authenticate"]


async def test_full_flow():
    async with running() as (client, fake_idp, yac):
        client_id = await _register(client)
        # the client_id is the sealed registration (pinned SDK behavior: the
        # registration handler returns the object register_client() changed)
        assert envelope.open_("client", client_id)["client_name"] == "Test Agent"

        code, verifier = await _login(client, fake_idp, client_id)
        r = await client.post("/token", data={
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": client_id, "redirect_uri": REDIRECT})
        assert r.status_code == 200, r.text
        tokens = r.json()
        assert 0 < tokens["expires_in"] <= 300 and tokens["refresh_token"]
        assert fake_idp.token_requests[0]["auth"].startswith("Basic ")

        # the code is single use (enforced by the IdP)
        r = await client.post("/token", data={
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": client_id, "redirect_uri": REDIRECT})
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

        r = await _mcp(client, tokens["access_token"], "tools/call",
                       {"name": "list_entities", "arguments": {"backend": "hosts", "type": "host"}})
        assert r.status_code == 200, r.text
        result = r.json()["result"]
        assert not result.get("isError"), result
        assert result["structuredContent"]["entities"][0]["name"] == "web01"
        upstream = yac.requests[-1].headers["authorization"].removeprefix("Bearer ")
        claims = jwt.decode(upstream, fake_idp.key).claims
        assert claims["sub"] == "alice-sub" and claims["aud"] == "yac-mcp"

        # refresh: new tokens, rotated IdP refresh token
        r = await client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id})
        assert r.status_code == 200, r.text
        refreshed = r.json()
        r = await _mcp(client, refreshed["access_token"], "tools/list")
        assert r.status_code == 200
        # the old IdP refresh token was rotated away
        r = await client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id})
        assert r.status_code == 400

        # IdP without id-token on refresh -> clear error
        fake_idp.refresh_returns_id_token = False
        r = await client.post("/token", data={
            "grant_type": "refresh_token", "refresh_token": refreshed["refresh_token"], "client_id": client_id})
        assert r.status_code == 400 and "id-token" in r.json()["error_description"]


async def test_remembered_consent_and_tool_errors():
    async with running() as (client, fake_idp, _):
        client_id = await _register(client)
        code, verifier = await _login(client, fake_idp, client_id, remember=True)
        # second login: the consent cookie skips the page
        r = await client.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
            "code_challenge": _pkce()[1], "code_challenge_method": "S256", "state": "s"})
        r = await client.get(r.headers["location"])
        assert r.status_code == 302 and r.headers["location"].startswith(f"{IDP}/authorize")

        r = await client.post("/token", data={
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": client_id, "redirect_uri": REDIRECT})
        token = r.json()["access_token"]
        r = await _mcp(client, token, "tools/call",
                       {"name": "read_entity", "arguments": {"backend": "nope", "type": "host", "name": "x"}})
        result = r.json()["result"]
        assert result["isError"] and 'no backend "nope"' in result["content"][0]["text"]


async def test_consent_csrf_and_deny():
    async with running() as (client, _, _):
        client_id = await _register(client)
        r = await client.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
            "code_challenge": _pkce()[1], "code_challenge_method": "S256", "state": "s"})
        consent_url = r.headers["location"]
        request = parse_qs(urlparse(consent_url).query)["request"][0]
        # cross-site auto-submit: no CSRF cookie
        async with httpx.AsyncClient(transport=client._transport, base_url=BASE) as other:  # pylint: disable=protected-access
            r = await other.post("/consent", data={"request": request, "csrf": "x", "decision": "allow"})
            assert r.status_code == 400
        r = await client.get(consent_url)
        csrf = r.text.split('name="csrf" value="')[1].split('"')[0]
        r = await client.post("/consent", data={"request": request, "csrf": csrf, "decision": "deny"})
        assert r.status_code == 302 and "error=access_denied" in r.headers["location"]


async def test_tokens_are_bound():
    async with running() as (client, fake_idp, _):
        client_a = await _register(client)
        client_b = await _register(client)
        code, verifier = await _login(client, fake_idp, client_a)
        r = await client.post("/token", data={
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": client_b, "redirect_uri": REDIRECT})
        assert r.status_code == 400  # code of client A, used by client B
        r = await client.post("/token", data={
            "grant_type": "authorization_code", "code": code, "code_verifier": "wrong" * 10,
            "client_id": client_a, "redirect_uri": REDIRECT})
        assert r.status_code == 400  # PKCE
        for wrong in (code, envelope.seal("refresh", {}), "garbage"):
            assert (await _mcp(client, wrong, "tools/list")).status_code == 401
        # an id-token for another client is rejected at the token endpoint
        with pytest.raises(Exception, match="another client"):
            await idp.validate_id_token(fake_idp.id_token(aud="vays"))


async def test_client_metadata_document(env):
    async with running() as (client, fake_idp, _):
        env(client_metadata_allow_private=True)
        url = "https://agent.test/oauth/client.json"
        oauth._cimd_cache.clear()  # pylint: disable=protected-access
        with respx.mock(assert_all_called=False) as router:
            router.route(host="agent.test").mock(return_value=httpx.Response(200, json={
                "client_id": url, "client_name": "CIMD Agent",
                "redirect_uris": ["http://127.0.0.1/callback"], "token_endpoint_auth_method": "none"}))
            router.route(host="idp.test").mock(side_effect=fake_idp.handle)
            # loopback redirect URIs may use any port (RFC 8252)
            code, verifier = await _login(client, fake_idp, url, redirect="http://127.0.0.1:5555/callback")
            r = await client.post("/token", data={
                "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                "client_id": url, "redirect_uri": "http://127.0.0.1:5555/callback"})
            assert r.status_code == 200, r.text
        oauth._cimd_cache.clear()  # pylint: disable=protected-access
        with respx.mock(assert_all_called=False) as router:
            router.route(host="agent.test").mock(return_value=httpx.Response(200, json={
                "client_id": "https://evil.test/x", "redirect_uris": ["https://evil.test/cb"]}))
            assert await oauth.StatelessProvider().get_client(url) is None
