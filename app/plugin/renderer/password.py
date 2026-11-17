"""
Renderer plugin for VAYS' `password`: the cleartext is passed in the tool's
`secrets` argument (never in the YAML) and stored as SHA-512 crypt hash
(`$6$<16 char salt>$...`, 5000 rounds, exactly like VAYS'
`src/utils/passwordHashes.ts`) or, with `save_password_as: plaintext`, as is.

Note: the cleartext still passed through the agent (and its LLM provider).
"""

from passlib.hash import sha512_crypt

from app.model.plg import Error, Keep, RendererContext, Set

ACCEPTS_SECRET = True

_HASHER = sha512_crypt.using(rounds=5000, salt_size=16)


def describe(options: dict, _schema: dict) -> str:
    stored = "as is" if options.get("save_password_as") == "plaintext" else "as SHA-512 crypt hash"
    return (
        "Password: pass the cleartext in the `secrets` argument keyed by this field's"
        f" location (the server stores it {stored}); keep the stored value otherwise."
        " Never write a cleartext into the YAML."
    )


def prepare(ctx: RendererContext):  # pylint: disable=too-many-return-statements
    if ctx.secret is not None:
        if ctx.options.get("save_password_as") == "plaintext":
            return Set(ctx.secret, {"set": True})
        return Set(_HASHER.hash(ctx.secret), {"set": True})
    if ctx.generate_requested:
        return Error("passwords cannot be generated, pass the cleartext in `secrets`")
    if ctx.agent_value_empty:
        if ctx.operation == "edit" and ctx.has_current and not ctx.in_array:
            return Set(ctx.current, {"kept": "stored value"})
        return Keep()
    if ctx.is_stored_value:
        return Keep()
    return Error(
        f'pass passwords in the `secrets` argument (e.g. {{"{ctx.loc}": "..."}}),'
        " never in the YAML"
    )


TEST_VECTORS = [
    (
        {"secret": "Hello world!"},
        lambda r: isinstance(r, Set)
        and r.value.startswith("$6$")
        and len(r.value.split("$")[2]) == 16
        and sha512_crypt.verify("Hello world!", r.value),
    ),
    (
        {"secret": "pw", "options": {"save_password_as": "plaintext"}},
        lambda r: isinstance(r, Set) and r.value == "pw",
    ),
    ({"agent_value": "cleartext"}, lambda r: isinstance(r, Error)),
    ({"agent_value": "$6$a$b", "stored_values": ("$6$a$b",)}, lambda r: isinstance(r, Keep)),
    ({}, lambda r: isinstance(r, Keep)),
    ({"agent_value": "~generate"}, lambda r: isinstance(r, Error)),
    (
        {"operation": "edit", "current": "$6$a$b"},
        lambda r: isinstance(r, Set) and r.value == "$6$a$b",
    ),
    (
        {"operation": "edit", "current": "$6$a$b", "pattern": "#/u/*/pw", "loc": "#/u/0/pw"},
        lambda r: isinstance(r, Keep),
    ),
]
