"""
Round-trip YAML handling (ruamel, configured like YAC's `app/lib/yaml.py`),
used to put generated values into the agent's YAML without losing comments,
key order or styles.

Raises: [app.model.err.InputError]
"""

import copy
import io
import re
from typing import Any

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from app import consts
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
# Not representable in a literal block (`|`): a CR or unicode line break
# would be read back as `\n`, other control characters not at all.
_NOT_LITERAL = re.compile(
    "[^\t\n\x20-\x7e\xa0-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]|[\u2028\u2029]"
)
y.representer.add_representer(
    str,
    lambda self, data: self.represent_scalar(
        "tag:yaml.org,2002:str",
        data,
        style="|" if "\n" in data and not _NOT_LITERAL.search(data) else None,
    ),
)
y.constructor.add_constructor(
    "tag:yaml.org,2002:timestamp", lambda self, data: self.construct_scalar(data)
)


# Like YAC (app/lib/yaml.py): the document as written may be small, but
# nested aliases expand exponentially as soon as the data is walked (schema
# validation, defaults, renderers): at most this many nodes once expanded.
MAX_NODES = 100_000

# A `%YAML` / `%TAG` directive at the start of a line (YAC refuses them).
_DIRECTIVE = re.compile("(?:^|[\n\r\x85\u2028\u2029])\ufeff?%(?:YAML|TAG)[ \t]")


def _assert_bounded(text: str, data: Any) -> None:
    """Refuse a document bigger than MAX_NODES once its aliases are expanded."""
    if "*" not in text or "&" not in text:
        return  # no anchor/alias pair: the data is as big as the text
    sizes: dict[int, int] = {}
    in_progress: set[int] = set()

    def size(node: Any) -> int:
        if isinstance(node, dict):
            children: Any = (x for item in node.items() for x in item)
        elif isinstance(node, (list, tuple, set)):
            children = node
        else:
            return 1
        key = id(node)
        if key in sizes:
            return sizes[key]
        if key in in_progress:
            raise InputError("The YAML contains an alias to itself")
        in_progress.add(key)
        total = 1
        for child in children:
            total += size(child)
            if total > MAX_NODES:
                raise InputError(
                    f"The YAML is too big once its aliases are expanded (more than"
                    f" {MAX_NODES} nodes)"
                )
        in_progress.discard(key)
        sizes[key] = total
        return total

    size(data)


def load(text: str | None) -> CommentedMap:
    """Load an entity document (a mapping; empty documents become `{}`)."""
    text = text or ""
    if len(text) > consts.ENV.max_yaml_size:
        raise InputError(
            f"The YAML is too big ({len(text)} characters, at most"
            f" {consts.ENV.max_yaml_size})"
        )
    if "%" in text and _DIRECTIVE.search(text):
        raise InputError("YAML directives (%YAML, %TAG) are not supported")
    # ruamel keeps the version of the last document it saw: never let one
    # document decide how the next one is parsed.
    y.version = None
    try:
        data = y.load(text)
        _assert_bounded(text, data)
    except ruamel.yaml.YAMLError as error:
        raise InputError(f"The YAML is not valid: {error}") from error
    except RecursionError as error:
        raise InputError("The YAML is nested too deeply") from error
    except (ValueError, IndexError) as error:
        # ruamel's scalar constructors leak these for tokens like `._` or `0x_`
        raise InputError(f"The YAML is not valid: invalid value ({error})") from error
    if data is None:
        return CommentedMap()
    if not isinstance(data, CommentedMap):
        raise InputError("The YAML document must be a mapping (key: value pairs)")
    return data


def dump(data: Any) -> str:
    buf = io.BytesIO()
    y.version = None  # no `%YAML` header inherited from a load
    try:
        y.dump(data, buf)
    except BaseException as error:
        # ruamel only resets its output state after a dump that went through:
        # left behind half-way, every later dump of this (shared) instance
        # would return an empty document (same as in YAC).
        y._output = None  # pylint: disable=protected-access
        y._context_manager = None  # pylint: disable=protected-access
        for attr in ("_serializer", "_emitter"):
            if hasattr(y, attr):
                delattr(y, attr)
        if isinstance(error, RecursionError):
            raise InputError("The data is nested too deeply") from error
        raise
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


def same_data(a: Any, b: Any) -> bool:
    """
    Whether two (loaded) documents hold the same data, as JSON sees it: `1`
    equals `1.0`, but bools never equal numbers (like YAC's `same_data`).
    """
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same_data(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same_data(x, z) for x, z in zip(a, b))
    pa, pb = plain(a), plain(b)
    if {type(pa), type(pb)} == {int, float}:
        return pa == pb
    return type(pa) is type(pb) and pa == pb


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
