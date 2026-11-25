"""
The operations behind the MCP tools: a YAML document flow on top of YAC.

Writing works like VAYS, minus the form: the agent's YAML is validated by YAC
(which also returns the schemas generated for that data), missing defaults
are filled in, the renderer plugins generate/hash/encrypt their fields, and
this repeats until nothing changes (the schemas can depend on the data).
Only then is the canonical YAML returned by YAC committed.

Raises: [app.model.err.InputError, app.model.err.ReadOnlyError,
         app.model.err.UpstreamError, app.model.err.EnvelopeError]
"""

import copy
import re
from dataclasses import dataclass, field
from typing import Any

from app import consts
from app.lib import backends
from app.lib import envelope
from app.lib import locs
from app.lib import renderers
from app.lib import schema
from app.lib import yaml as yamllib
from app.lib.yac import Yac
from app.model.err import InputError, ReadOnlyError, UpstreamError

MAX_ROUNDS = 4
EDIT_TOKEN_TTL = 7 * 86400


@dataclass
class Prepared:
    yaml: str
    valid: bool
    errors: list[dict]
    reports: list[dict] = field(default_factory=list)
    defaults: list[str] = field(default_factory=list)
    usages: list[dict] = field(default_factory=list)


def check_name(name: str, what: str = "name") -> None:
    if not re.match(consts.NAME_PATTERN, name or ""):
        raise InputError(f'The {what} "{name}" must match {consts.NAME_PATTERN}')


def check_writable() -> None:
    if consts.ENV.read_only:
        raise ReadOnlyError("This MCP server is read-only: changes must be made in VAYS")


def commit_message(message: str) -> str:
    msg = consts.COMMIT_SUFFIX
    if message.strip():
        msg = f"{message.strip()}\n\n{consts.COMMIT_SUFFIX}"
    if not re.match(consts.MSG_PATTERN, msg):
        raise InputError(
            "The message may only contain letters (incl. äöü), digits, spaces, line"
            ' breaks and @ ( ) " . , _ / -'
        )
    return msg


def _trim_type(typ: dict) -> dict:
    keys = ("name", "title", "description", "create", "edit", "delete")
    trimmed = {k: typ[k] for k in keys if k in typ}
    for key in ("name_pattern", "name_example", "name_generated"):
        if typ.get(key):
            trimmed[key] = typ[key]
    if typ.get("options"):
        trimmed["options"] = [{"name": o["name"], "title": o["title"]} for o in typ["options"]]
    if typ.get("actions"):
        trimmed["actions"] = [
            {k: a[k] for k in ("name", "title", "description", "dangerous") if k in a}
            for a in typ["actions"]
        ]
    if typ.get("logs"):
        trimmed["logs"] = [
            {k: lg[k] for k in ("name", "title", "description", "renderer") if lg.get(k)}
            for lg in typ["logs"]
        ]
    return trimmed


async def list_types(client: Yac) -> list[dict]:
    return [_trim_type(t) for t in await client.types()]


async def find_type(client: Yac, type_name: str) -> dict:
    for typ in await client.types():
        if typ.get("name") == type_name:
            return typ
    raise InputError(f'There is no type "{type_name}" in backend "{client.backend.name}"')


async def list_entities(
    client: Yac, type_name: str, search: str, skip: int, limit: int
) -> dict:
    if not re.match(consts.SEARCH_PATTERN, search):
        raise InputError(f"The search must match {consts.SEARCH_PATTERN}")
    result = await client.entities(type_name, search, skip, limit)
    keys = ("name", "link", "options", "perms")
    return {"entities": [{k: e[k] for k in keys if e.get(k)} for e in result["list"]]}


def _schema_view(schemas: dict) -> dict:
    return {
        "json_schema": schema.trim(schemas["json_schema"]),
        "field_notes": renderers.describe(schemas["ui_schema"], schemas["json_schema"]),
    }


def edit_token(client: Yac, type_name: str, name: str, yaml_text: str) -> str:
    data = {"backend": client.backend.name, "type": type_name, "name": name, "yaml": yaml_text}
    return envelope.seal("base", data, ttl=EDIT_TOKEN_TTL)


async def read_entity(client: Yac, type_name: str, name: str) -> dict:
    yaml_text = await client.entity_yaml(type_name, name)
    # Like VAYS' edit mode: the schema of an edit (with what the user may not
    # change, `yac_perms` / `yac_editable`) and the usage of the limits, which
    # YAC only measures for the operations they apply to (not for a read). A
    # user who may not edit gets the display schema of a read.
    result = await client.validate(
        {"operation": "edit", "type": type_name, "name": name,
         "entity": {"name": name, "yaml_old": yaml_text, "yaml_new": yaml_text}}
    )
    if "edt" not in result.get("perms", []):
        result = await client.validate({"operation": "read", "type": type_name, "name": name})
    return {
        "yaml": yaml_text,
        "perms": result.get("perms", []),
        **_schema_view(result["schemas"]),
        "usages": result.get("usages", []),
        "edit_token": edit_token(client, type_name, name, yaml_text),
    }


def _seed_yaml(doc: Any) -> str:
    """The new document, with the configured comment (like VAYS' create mode)."""
    body = yamllib.dump(doc)
    body = body[4:] if body.startswith("---\n") else body[3:].lstrip()
    comment = backends.config().yaml_comment
    lines = "".join(f"# {ln}\n" if ln.strip() else "#\n" for ln in comment.split("\n"))
    return f"---\n{lines if comment.strip() else ''}{body}"


def _fill_defaults(doc: Any, json_schema: Any, filled: dict[str, Any]) -> bool:
    """
    Fill in the missing defaults and let the ones filled in earlier (in
    `filled`, loc -> value) follow the defaults of a newer schema, like VAYS.
    Returns whether the document changed.
    """
    changed = schema.refresh_defaults(doc, json_schema, filled)
    added = schema.apply_defaults(doc, json_schema)
    for loc in added:
        filled[loc] = copy.deepcopy(yamllib.plain(locs.get(doc, locs.parse(loc))))
    return bool(changed or added)


async def new_entity(client: Yac, type_name: str) -> dict:
    typ = _trim_type(await find_type(client, type_name))
    doc = yamllib.load("")
    filled: dict[str, Any] = {}
    for _ in range(MAX_ROUNDS):
        body = {"operation": "create", "type": type_name, "name": None,
                "entity": {"name": None, "yaml": yamllib.dump(doc)}}
        result = await client.validate(body)
        if not _fill_defaults(doc, result["schemas"]["json_schema"], filled):
            break
    defaults = list(filled)
    name_info = {k: typ[k] for k in ("name_pattern", "name_example", "name_generated") if k in typ}
    return {
        "yaml": _seed_yaml(doc),
        "name": name_info,
        **_schema_view(result["schemas"]),
        "defaults_applied": defaults,
        "usages": result.get("usages", []),
    }


def _validate_body(type_name, operation, name, yaml_text, stored_yaml) -> dict:
    if operation == "create":
        return {"operation": "create", "type": type_name, "name": None,
                "entity": {"name": name, "yaml": yaml_text}}
    return {"operation": "edit", "type": type_name, "name": name,
            "entity": {"name": name, "yaml_old": stored_yaml, "yaml_new": yaml_text}}


def _errors(result: dict, state: renderers.State) -> list[dict]:
    errors: list[dict] = []
    request = result.get("request") or {}
    if not request.get("valid", True):
        errors.append({"loc": None, "message": request.get("message")})
    schemas = result["schemas"]
    if not schemas.get("valid", True):
        errors.extend(schema.all_errors(schemas["json_schema"], schemas.get("data")))
        loc = schemas.get("data_loc")
        if not any(e["loc"] == loc for e in errors):
            errors.insert(0, {"loc": loc, "message": schemas.get("message")})
    known = {(e["loc"], e["message"]) for e in errors}
    errors.extend(e for e in state.errors if (e["loc"], e["message"]) not in known)
    return errors


async def prepare(  # pylint: disable=too-many-locals
    client: Yac,
    type_name: str,
    operation: str,
    name: str | None,
    yaml_text: str,
    stored_yaml: str | None,
    secrets: dict[str, str] | None,
) -> Prepared:
    doc = yamllib.load(yaml_text)
    stored = yamllib.plain(yamllib.load(stored_yaml)) if stored_yaml is not None else None
    state = renderers.State(operation=operation, stored=stored, secrets=dict(secrets or {}))
    filled: dict[str, Any] = {}
    for round_ in range(1, MAX_ROUNDS + 1):
        body = _validate_body(type_name, operation, name, yamllib.dump(doc), stored_yaml)
        result = await client.validate(body)
        if round_ == MAX_ROUNDS:
            break
        schemas = result["schemas"]
        defaults_changed = _fill_defaults(doc, schemas["json_schema"], filled)
        changed = await renderers.apply(state, doc, schemas["ui_schema"], schemas["json_schema"])
        if not defaults_changed and not changed:
            break
    renderers.finish(state, doc)
    errors = _errors(result, state)
    return Prepared(
        yaml=result["schemas"].get("yaml") or yamllib.dump(doc),
        valid=not errors,
        errors=errors,
        reports=state.reports,
        defaults=list(filled),
        usages=result.get("usages", []),
    )


def _dry_run_reports(reports: list[dict]) -> list[dict]:
    hidden = ("value", "secret", "note")
    return [{k: v for k, v in r.items() if k not in hidden} for r in reports]


async def _stored_yaml(client: Yac, type_name: str, name: str, token: str | None) -> str:
    if not token:
        return await client.entity_yaml(type_name, name)
    base = envelope.open_("base", token)
    if (base["backend"], base["type"], base["name"]) != (client.backend.name, type_name, name):
        raise InputError("The edit_token belongs to another entity")
    return base["yaml"]


async def _merged_yaml(client: Yac, type_name: str, name: str, stored: str, data: dict) -> str:
    body = {"operation": "edit", "type": type_name, "name": name,
            "entity": {"name": name, "data": data, "yaml_old": stored, "yaml_base": stored}}
    result = await client.validate(body)
    return result["schemas"]["yaml"]


async def validate(
    client: Yac,
    type_name: str,
    operation: str,
    name: str | None,
    yaml_text: str | None,
    data: dict | None,
    token: str | None,
    secrets: dict[str, str] | None,
) -> dict:
    stored = None
    if operation == "edit":
        if not name:
            raise InputError("`name` is required to validate an edit")
        stored = await _stored_yaml(client, type_name, name, token)
        if data is not None:
            yaml_text = await _merged_yaml(client, type_name, name, stored, data)
    if yaml_text is None:
        raise InputError("Pass the entity as `yaml` (or as `data` patch for an edit)")
    agent_yaml = yaml_text if data is None else None
    prepared = await prepare(client, type_name, operation, name, yaml_text, stored, secrets)
    unchanged = {}
    if stored is not None and prepared.valid and _unchanged(stored, prepared, agent_yaml):
        unchanged = {"unchanged": True, "hint": UNCHANGED_HINT}
    return {
        **unchanged,
        "valid": prepared.valid,
        "errors": prepared.errors,
        "would_generate": _dry_run_reports(prepared.reports),
        "defaults_applied": prepared.defaults,
        "usages": prepared.usages,
    }


def _unchanged(stored: str, prepared: Prepared, yaml_text: str | None) -> bool:
    """
    Whether an edit would change nothing, so there is nothing to commit (YAC
    refuses such a write). Re-sent stored values are no change (like a YAC
    patch), and neither is the stored document sent back as it is, even if
    YAC would format it differently.
    """
    if prepared.yaml == stored:
        return True
    if not yamllib.same_data(yamllib.load(prepared.yaml), yamllib.load(stored)):
        return False
    return yaml_text is None or yaml_text.strip() == stored.strip()


UNCHANGED_HINT = "The entity already has this content: there is nothing to commit."


def _not_committed(prepared: Prepared) -> dict:
    return {
        "committed": False,
        "errors": prepared.errors,
        "hint": "Nothing was changed. Fix the errors and try again.",
    }


async def create(
    client: Yac,
    type_name: str,
    name: str | None,
    yaml_text: str,
    secrets: dict[str, str] | None,
    message: str,
    run: list[str],
) -> dict:
    check_writable()
    if name is not None:
        check_name(name)
    msg = commit_message(message)
    prepared = await prepare(client, type_name, "create", name, yaml_text, None, secrets)
    if not prepared.valid:
        return _not_committed(prepared)
    diff = await client.create(type_name, {"name": name, "yaml": prepared.yaml}, msg, run)
    return {
        "committed": True,
        "name": diff.get("name", name),
        "patch": diff.get("patch", ""),
        "generated": prepared.reports,
        "defaults_applied": prepared.defaults,
    }


async def edit(  # pylint: disable=too-many-locals
    client: Yac,
    type_name: str,
    name: str,
    yaml_text: str | None,
    data: dict | None,
    token: str | None,
    secrets: dict[str, str] | None,
    message: str,
    run: list[str],
) -> dict:
    check_writable()
    check_name(name)
    if (yaml_text is None) == (data is None):
        raise InputError("Pass either `yaml` (the whole document) or `data` (a patch)")
    msg = commit_message(message)
    stored = await _stored_yaml(client, type_name, name, token)
    agent_yaml = yaml_text
    if data is not None:
        yaml_text = await _merged_yaml(client, type_name, name, stored, data)
    prepared = await prepare(client, type_name, "edit", name, yaml_text or "", stored, secrets)
    if not prepared.valid:
        return _not_committed(prepared)
    if _unchanged(stored, prepared, agent_yaml):
        return {"committed": False, "unchanged": True, "hint": UNCHANGED_HINT}
    body = {"name": name, "yaml_old": stored, "yaml_new": prepared.yaml}
    try:
        diff = await client.replace(type_name, name, body, msg, run)
    except UpstreamError as error:
        if error.status == 409:
            raise InputError(
                f"{error.message} - the entity was changed in the meantime: read it"
                " again and redo the change"
            ) from error
        raise
    return {
        "committed": True,
        "name": diff.get("name", name),
        "patch": diff.get("patch", ""),
        "generated": prepared.reports,
        "defaults_applied": prepared.defaults,
    }


async def delete(client: Yac, type_name: str, name: str, message: str, run: list[str]) -> dict:
    check_writable()
    check_name(name)
    await client.delete(type_name, name, commit_message(message), run)
    return {"deleted": name}


async def run_action(client: Yac, type_name: str, name: str, action: str) -> dict:
    check_writable()
    check_name(name)
    check_name(action, "action")
    await client.run_action(type_name, name, action)
    return {"started": action, "hint": "Use read_logs to follow its progress (if it logs)."}


async def read_logs(client: Yac, type_name: str, name: str, log: str | None) -> dict:
    if log is None:
        return {"logs": await client.logs(type_name, name)}
    check_name(log, "log")
    result = await client.log_content(type_name, name, log)
    content = str(result.get("content") or "")
    limit = consts.ENV.max_log_content
    answer = {"log": log, "time": result.get("time", ""), "content": content[:limit]}
    if len(content) > limit:
        answer["truncated"] = f"Only the first {limit} of {len(content)} characters"
    return answer
