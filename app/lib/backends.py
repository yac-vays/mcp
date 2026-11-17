"""
The YAC backends, read once from the VAYS-compatible config file (like YAC
reads its specs file once: a change requires a restart).

Raises: [app.model.err.ConfigError, app.model.err.InputError]
"""

import json
import logging
from dataclasses import dataclass
from functools import lru_cache

from app import consts
from app.model.err import ConfigError, InputError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Backend:
    name: str
    title: str
    url: str


@dataclass(frozen=True)
class Config:
    backends: tuple[Backend, ...]
    yaml_comment: str


@lru_cache(maxsize=1)
def config() -> Config:
    try:
        with open(consts.ENV.config, encoding="utf-8") as file:
            raw = json.load(file)
    except (OSError, ValueError) as error:
        raise ConfigError(f"Could not read the config file {consts.ENV.config}: {error}") from error
    try:
        backends = tuple(
            Backend(name=b["name"], title=b.get("title", b["name"]), url=b["url"].rstrip("/"))
            for b in raw["backends"]
        )
    except (KeyError, TypeError, AttributeError) as error:
        raise ConfigError(f"Invalid `backends` in {consts.ENV.config}: {error}") from error
    if not backends:
        raise ConfigError(f"No `backends` in {consts.ENV.config}")
    comment = raw.get("yamlComment", consts.DEFAULT_YAML_COMMENT)
    return Config(backends=backends, yaml_comment=comment if isinstance(comment, str) else "")


def get(name: str) -> Backend:
    for backend in config().backends:
        if backend.name == name:
            return backend
    names = ", ".join(b.name for b in config().backends)
    raise InputError(f'There is no backend "{name}" (available: {names})')
