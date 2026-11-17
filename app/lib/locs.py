"""
Data locations in YAC syntax (`#/key/0/sub`, JSON pointer escaping with
`~0`/`~1`), and access to nested dict/list data by token lists.

Raises: [app.model.err.InputError]
"""

from typing import Any

from app.model.err import InputError
from app.model.plg import MISSING

# Wildcard token for "every item of an array" in field patterns.
ITEMS = "*"


def parse(loc: str) -> list[str]:
    if loc in ("#", "#/"):
        return []
    if not loc.startswith("#/"):
        raise InputError(f'"{loc}" is not a data location like "#/key/subkey"')
    return [t.replace("~1", "/").replace("~0", "~") for t in loc[2:].split("/")]


def build(tokens: list) -> str:
    if not tokens:
        return "#"
    return "#/" + "/".join(str(t).replace("~", "~0").replace("/", "~1") for t in tokens)


def get(data: Any, tokens: list) -> Any:
    for token in tokens:
        if isinstance(data, dict):
            if token not in data:
                return MISSING
            data = data[token]
        elif isinstance(data, list):
            try:
                index = int(token)
            except (TypeError, ValueError):
                return MISSING
            if not 0 <= index < len(data):
                return MISSING
            data = data[index]
        else:
            return MISSING
    return data


def expand(data: Any, pattern: list) -> list[list]:
    """
    Concrete token lists for a pattern with `ITEMS` wildcards, one per array
    item present in `data`. Object keys are kept even if missing in `data`
    (a field can be generated where nothing is stored yet), but nothing is
    expanded below a missing array.
    """
    results: list[list] = [[]]
    for token in pattern:
        nxt = []
        for prefix in results:
            if token == ITEMS:
                items = get(data, prefix)
                if isinstance(items, list):
                    nxt.extend([*prefix, str(i)] for i in range(len(items)))
            else:
                nxt.append([*prefix, token])
        results = nxt
    return results


def matches(pattern: list, tokens: list) -> bool:
    return len(pattern) == len(tokens) and all(
        p == t or (p == ITEMS and t.isdigit()) for p, t in zip(pattern, tokens)
    )
