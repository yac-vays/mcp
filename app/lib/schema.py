"""
Helpers around the schemas YAC generates per request (`/validate`):

- the ui_schema is the source of the VAYS options (`renderer`,
  `renderer_options`, `initial`, ...) per field, including nested objects
  (`options.detail`) and array items (`options.details.elements`),
- defaults are materialized like VAYS does (ajv `useDefaults`),
- the json_schema is trimmed for agents and checked for all errors at once.

Raises: []
"""

import copy
from dataclasses import dataclass
from typing import Any

import jsonschema

from app.lib import locs
from app.lib import yaml as yamllib
from app.lib.locs import ITEMS


@dataclass(frozen=True)
class Control:
    pattern: tuple
    """Data location tokens; `ITEMS` stands for every array item."""
    options: dict

    @property
    def loc(self) -> str:
        return locs.build(list(self.pattern))


def _scope_tokens(scope: str) -> list[str]:
    tokens = locs.parse(scope) if scope not in ("#", "") else []
    # "#/properties/a/properties/b" -> ["a", "b"]
    return [t for i, t in enumerate(tokens) if i % 2 == 1]


def controls(ui_schema: Any, prefix: tuple = ()) -> list[Control]:
    """All Controls of a (YAC-generated) ui_schema with their data patterns."""
    found: list[Control] = []
    if not isinstance(ui_schema, dict):
        return found
    if ui_schema.get("type") == "Control":
        pattern = prefix + tuple(_scope_tokens(str(ui_schema.get("scope", "#"))))
        options = ui_schema.get("options") or {}
        found.append(Control(pattern, options))
        detail = options.get("detail")
        if isinstance(detail, dict):
            found.extend(controls(detail, pattern))
        details = options.get("details")
        if isinstance(details, dict):
            for element in details.get("elements") or []:
                found.extend(controls(element, pattern + (ITEMS,)))
    for element in ui_schema.get("elements") or []:
        found.extend(controls(element, prefix))
    return found


def node(json_schema: Any, pattern: tuple | list) -> dict:
    """The schema node at a pattern (`{}` if it cannot be resolved)."""
    current = json_schema
    for token in pattern:
        if not isinstance(current, dict):
            return {}
        properties = current.get("properties") or {}
        if token == ITEMS or (token.isdigit() and token not in properties):
            current = current.get("items")
        else:
            current = properties.get(token)
    return current if isinstance(current, dict) else {}


def apply_defaults(data: Any, json_schema: Any, prefix: tuple = ()) -> list[str]:
    """
    Fill in missing properties that have a `default` (deep copies), recursing
    into objects and array items, like ajv's `useDefaults` that VAYS uses.
    Returns the locations that were filled in.
    """
    filled: list[str] = []
    if not isinstance(json_schema, dict):
        return filled
    if isinstance(data, dict):
        for key, sub in (json_schema.get("properties") or {}).items():
            if not isinstance(sub, dict):
                continue
            if key not in data and "default" in sub:
                default = copy.deepcopy(sub["default"])
                _set_plain_or_rt(data, key, default)
                filled.append(locs.build([*prefix, key]))
            if key in data:
                filled.extend(apply_defaults(data[key], sub, (*prefix, key)))
    elif isinstance(data, list) and isinstance(json_schema.get("items"), dict):
        for index, item in enumerate(data):
            filled.extend(apply_defaults(item, json_schema["items"], (*prefix, str(index))))
    return filled


def refresh_defaults(data: Any, json_schema: Any, filled: dict[str, Any]) -> list[str]:
    """
    Bring the values the gateway filled in itself (`filled`: loc -> value as
    filled in) to the defaults of a newer schema, like VAYS: a value still
    equal to what was filled in follows a changed default and is removed with
    a default that is gone. Values changed since are left alone (and dropped
    from `filled`). Returns the locations that were changed or removed.
    """
    changed: list[str] = []
    for loc in sorted(filled, key=len):
        if loc not in filled:
            continue
        tokens = locs.parse(loc)
        parent = locs.get(data, tokens[:-1])
        if not isinstance(parent, dict) or tokens[-1] not in parent:
            del filled[loc]
            continue
        if not yamllib.same_data(parent[tokens[-1]], filled[loc]):
            del filled[loc]
            continue
        sub = node(json_schema, tokens)
        if "default" not in sub:
            del parent[tokens[-1]]
        elif not yamllib.same_data(sub["default"], filled[loc]):
            _set_plain_or_rt(parent, tokens[-1], copy.deepcopy(sub["default"]))
        else:
            continue
        changed.append(loc)
        # Whatever was filled in below the old value went with it.
        for nested in [n for n in filled if n.startswith(f"{loc}/")]:
            del filled[nested]
        if "default" in sub:
            filled[loc] = copy.deepcopy(sub["default"])
        else:
            del filled[loc]
    return changed


def _set_plain_or_rt(data: dict, key: str, value: Any) -> None:
    # Keep ruamel documents ruamel-typed so they can be dumped with comments.
    if hasattr(data, "ca"):
        # pylint: disable=import-outside-toplevel
        from ruamel.yaml.comments import CommentedMap, CommentedSeq

        if isinstance(value, dict):
            value = CommentedMap(value)
        elif isinstance(value, list):
            value = CommentedSeq(value)
    data[key] = value


def trim(json_schema: Any) -> Any:
    """Remove the form-only `vays_*` keywords (they mean nothing to agents)."""
    if isinstance(json_schema, dict):
        return {
            k: trim(v) for k, v in json_schema.items() if not str(k).startswith("vays_")
        }
    if isinstance(json_schema, list):
        return [trim(v) for v in json_schema]
    return json_schema


def all_errors(json_schema: dict, data: Any, limit: int = 20) -> list[dict]:
    """
    Every schema error (YAC only reports the first one). Unknown formats and
    YAC's custom keywords are ignored here; YAC stays the authority.
    """
    try:
        validator = jsonschema.Draft7Validator(json_schema)
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    except jsonschema.exceptions.SchemaError:
        return []
    return [
        {
            "loc": locs.build([str(p) for p in error.absolute_path]),
            "message": error.message,
        }
        for error in errors[:limit]
    ]
