"""
The contract between the gateway core and the renderer plugins
(`app/plugin/renderer/*.py`, see the README there).
"""

import secrets
from dataclasses import dataclass, field
from typing import Any, Literal

from app import consts


class _Missing:
    """Marks a value that is not present at all (different from `None`)."""

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING: Any = _Missing()


@dataclass(frozen=True)
class Keep:
    """Leave the value as written by the agent."""


@dataclass(frozen=True)
class Set:  # pylint: disable=redefined-builtin
    """
    Store `value`. `report` is merged into what the tool result tells the agent
    about this field; it must never contain a secret unless
    `ctx.reveal_secrets` is true.
    """

    value: Any
    report: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Unset:
    """Remove the key."""


@dataclass(frozen=True)
class Error:
    """Reject the request; the message is shown to the agent."""

    message: str


Result = Keep | Set | Unset | Error


@dataclass(frozen=True)
class RendererContext:  # pylint: disable=too-many-instance-attributes
    operation: Literal["create", "edit"]
    loc: str
    """Concrete data location, e.g. `#/users/0/password`."""
    pattern: str
    """The field's location pattern, `*` for array items: `#/users/*/password`."""
    renderer: str
    options: dict
    """`vays_options.renderer_options` (defaults are up to the plugin)."""
    schema: dict
    """The field's (generated) JSON schema node."""
    agent_value: Any = MISSING
    """What the agent wrote at `loc` (may be the `~generate` marker)."""
    current: Any = MISSING
    """The stored value at `loc` before this operation (edit only)."""
    stored_values: tuple = ()
    """All stored values of this field (all array items); lets a plugin
    recognize values copied from the stored data even if items moved."""
    secret: str | None = None
    """The cleartext passed for `loc` in the tool's `secrets` argument."""
    reveal_secrets: bool = False

    @property
    def has_default(self) -> bool:
        return "default" in self.schema

    @property
    def generate_requested(self) -> bool:
        return self.agent_value == consts.MARKER_GENERATE

    @property
    def agent_value_empty(self) -> bool:
        return self.agent_value is MISSING or self.agent_value in (None, "")

    @property
    def is_stored_value(self) -> bool:
        """The agent value equals a stored value of this field."""
        return self.agent_value is not MISSING and any(
            self.agent_value == v for v in self.stored_values
        )

    @property
    def in_array(self) -> bool:
        """The field is (inside) an array item; `current` may then belong to an
        item that moved, so do not restore stored values by location."""
        return "*" in self.pattern.split("/")

    @property
    def has_current(self) -> bool:
        return self.current is not MISSING and self.current not in (None, "")

    @staticmethod
    def random(alphabet: str, length: int) -> str:
        """
        Cryptographically uniform random string from `alphabet` (distinct
        characters, at most 256), like VAYS' `randomFromAlphabet`.
        """
        chars = list(dict.fromkeys(alphabet))
        if not chars or len(chars) > 256:
            raise ValueError("the alphabet needs 1 to 256 distinct characters")
        return "".join(secrets.choice(chars) for _ in range(length))
