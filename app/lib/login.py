"""
The browser part of the login: the consent page (required for an OAuth proxy
with a single upstream client, against confused-deputy attacks) and the
callback from the upstream IdP. Stateless like the rest: the pending request
travels in sealed envelopes, consent is remembered in a sealed cookie and the
consent form is protected by a double-submit CSRF cookie (SameSite=Strict).

Raises: []
"""

import base64
import hashlib
import hmac
import html
import logging
import secrets
from urllib.parse import urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from app import consts
from app.lib import envelope
from app.lib import idp
from app.lib.oauth import StatelessProvider
from app.model.err import EnvelopeError, IdPError

logger = logging.getLogger(__name__)

CONSENT_COOKIE = "yac_mcp_consent"
CSRF_COOKIE = "yac_mcp_csrf"
MAX_REMEMBERED = 20

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;
line-height:1.5}}code{{background:#eee;padding:0 .2rem}}button{{font-size:1rem;
padding:.4rem 1rem;margin-right:.5rem}}</style></head><body>{body}</body></html>"""


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(_PAGE.format(title=html.escape(title), body=body), status_code=status)


def _error(message: str) -> HTMLResponse:
    return _page(
        "Login failed",
        f"<h1>Login failed</h1><p>{html.escape(message)}</p>"
        "<p>Start the login again from your MCP client.</p>",
        400,
    )


def _redirect(base: str, **params: str | None) -> RedirectResponse:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    return RedirectResponse(f"{base}{'&' if '?' in base else '?'}{query}", status_code=302)


def _consent_id(authz: dict) -> str:
    raw = f"{authz['client_id']}\n{authz['redirect_uri']}".encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:18]).decode()


def _remembered(request: Request) -> list[str]:
    cookie = request.cookies.get(CONSENT_COOKIE)
    if not cookie:
        return []
    try:
        return list(envelope.open_("consent", cookie).get("clients", []))
    except EnvelopeError:
        return []


def _secure() -> bool:
    return consts.ENV.public_url.startswith("https://")


async def _to_idp(authz: dict) -> Response:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    nonce = secrets.token_urlsafe(24)
    state = envelope.seal(
        "login", {"authz": authz, "verifier": verifier, "nonce": nonce}, ttl=consts.ENV.login_ttl
    )
    try:
        url = await idp.authorization_url(state, nonce, challenge)
    except IdPError as error:
        return _error(str(error))
    return RedirectResponse(url, status_code=302)


def routes(provider: StatelessProvider) -> list[Route]:
    async def consent(request: Request) -> Response:  # pylint: disable=too-many-return-statements
        form = await request.form() if request.method == "POST" else {}
        token = form.get("request") or request.query_params.get("request", "")
        try:
            authz = envelope.open_("authz", str(token))
        except EnvelopeError as error:
            return _error(f"The login request is {error}.")
        client = await provider.get_client(authz["client_id"])
        if client is None:
            return _error("The application is not (or no longer) registered.")
        consent_id = _consent_id(authz)

        if request.method == "GET":
            if consent_id in _remembered(request):
                return await _to_idp(authz)
            csrf = secrets.token_urlsafe(24)
            name = (
                client.client_name
                or urlparse(str(authz["client_id"])).netloc
                or "An application"
            )
            target = urlparse(authz["redirect_uri"])
            body = (
                "<h1>Allow access to YAC?</h1>"
                f"<p><b>{html.escape(name)}</b> wants to access the YAC backends"
                " (configuration data) <b>as you</b>, with all your permissions there."
                f" After the login, you will be sent back to"
                f" <code>{html.escape(target.scheme)}://{html.escape(target.netloc)}</code>.</p>"
                "<p>Only allow this if you started the login from this application.</p>"
                f'<form method="post" action="{consts.CONSENT_PATH}">'
                f'<input type="hidden" name="request" value="{html.escape(str(token))}">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                '<p><label><input type="checkbox" name="remember" value="1" checked>'
                " Remember my decision for this application</label></p>"
                '<button name="decision" value="allow">Allow</button>'
                '<button name="decision" value="deny">Deny</button></form>'
            )
            response = _page("Allow access to YAC?", body)
            response.set_cookie(
                CSRF_COOKIE, csrf, max_age=consts.ENV.login_ttl, path=consts.CONSENT_PATH,
                secure=_secure(), httponly=True, samesite="strict",
            )
            return response

        cookie = request.cookies.get(CSRF_COOKIE, "")
        if not cookie or not hmac.compare_digest(cookie, str(form.get("csrf", ""))):
            return _error("The consent form expired or was not submitted from this page.")
        if form.get("decision") != "allow":
            return _redirect(authz["redirect_uri"], error="access_denied", state=authz["state"])
        response = await _to_idp(authz)
        if form.get("remember"):
            clients = [c for c in _remembered(request) if c != consent_id]
            clients = [consent_id, *clients][:MAX_REMEMBERED]
            response.set_cookie(
                CONSENT_COOKIE,
                envelope.seal("consent", {"clients": clients}, ttl=consts.ENV.consent_max_age),
                max_age=consts.ENV.consent_max_age, path=consts.CONSENT_PATH,
                secure=_secure(), httponly=True, samesite="lax",
            )
        response.delete_cookie(CSRF_COOKIE, path=consts.CONSENT_PATH)
        return response

    async def callback(request: Request) -> Response:
        try:
            login = envelope.open_("login", request.query_params.get("state", ""))
        except EnvelopeError as error:
            return _error(f"The login state is {error}.")
        authz = login["authz"]
        if "error" in request.query_params or "code" not in request.query_params:
            logger.info(f"Login failed at the IdP: {request.query_params.get('error')}")
            return _redirect(authz["redirect_uri"], error="access_denied", state=authz["state"])
        code = envelope.seal(
            "code",
            {
                "authz": authz,
                "idp_code": request.query_params["code"],
                "verifier": login["verifier"],
                "nonce": login["nonce"],
            },
            ttl=consts.ENV.code_ttl,
        )
        return _redirect(authz["redirect_uri"], code=code, state=authz["state"])

    return [
        Route(consts.CONSENT_PATH, consent, methods=["GET", "POST"]),
        Route(consts.CALLBACK_PATH, callback, methods=["GET"]),
    ]
