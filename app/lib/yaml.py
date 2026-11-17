"""
Round-trip YAML handling (ruamel, configured like YAC's `app/lib/yaml.py`),
used to put generated values into the agent's YAML without losing comments,
key order or styles.

Raises: [app.model.err.InputError]
"""

import copy
import io
from typing import Any

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from app.lib import locs
from app.model.err import InputError
from app.model.plg import MISSING

y = ruamel.yaml.YAML(typ="rt")
y.indent(mapping=2, sequence=4, offset=2)
y.preserve_quotes = True
y.explicit_start = True
y.width = 4096
y.representer.add_representer(
    type(None),
    lambda self, data: self.represent_scalar("tag:yaml.org,2002:null", "null"),
)
y.representer.add_representer(
    str,
    lambda self, data: self.represent_scalar(
        "tag:yaml.org,2002:str", data, style="|" if "\n" in data else None
    ),
)
y.constructor.add_constructor(
    "tag:yaml.org,2002:timestamp", lambda self, data: self.construct_scalar(data)
)


def load(text: str | None) -> CommentedMap:
    """Load an entity document (a mapping; empty documents become `{}`)."""
    try:
        data = y.load(text or "")
    except ruamel.yaml.YAMLError as error:
        raise InputError(f"The YAML is not valid: {error}") from error
    if data is None:
        return CommentedMap()
    if not isinstance(data, CommentedMap):
        raise InputError("The YAML document must be a mapping (key: value pairs)")
    return data


def dump(data: Any) -> str:
    buf = io.BytesIO()
    y.dump(data, buf)
    return buf.getvalue().decode("utf-8")


def plain(data: Any) -> Any:  # pylint: disable=too-many-return-statements
    """Convert ruamel types into plain dicts, lists and scalars."""
    if isinstance(data, dict):
        return {str(k): plain(v) for k, v in data.items()}
    if isinstance(data, list):
        return [plain(v) for v in data]
    if isinstance(data, ruamel.yaml.scalarbool.ScalarBoolean):
        return bool(data)
    if isinstance(data, str):
        return str(data)
    if isinstance(data, bool):
        return data
    if isinstance(data, int):
        return int(data)
    if isinstance(data, float):
        return float(data)
    return data


def set_value(doc: CommentedMap, tokens: list, value: Any) -> None:
    """Set a value, creating missing intermediate mappings (never list items)."""
    parent: Any = doc
    for token in tokens[:-1]:
        child = locs.get(parent, [token])
        if child is MISSING or child is None:
            if not isinstance(parent, dict):
                raise InputError(f"Cannot create {locs.build(tokens)}: missing list item")
            parent[token] = CommentedMap()
            child = parent[token]
        parent = child
    last = tokens[-1]
    value = copy.deepcopy(value)
    if isinstance(value, dict) and not isinstance(value, CommentedMap):
        value = CommentedMap(value)
    elif isinstance(value, list) and not isinstance(value, CommentedSeq):
        value = CommentedSeq(value)
    if isinstance(parent, list):
        parent[int(last)] = value
    elif isinstance(parent, dict):
        parent[last] = value
    else:
        raise InputError(f"Cannot set {locs.build(tokens)}: the parent is not a mapping")


def delete_value(doc: CommentedMap, tokens: list) -> None:
    parent = locs.get(doc, tokens[:-1])
    if isinstance(parent, dict) and tokens[-1] in parent:
        del parent[tokens[-1]]
