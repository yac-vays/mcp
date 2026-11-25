"""
Core of the renderer plugins (`app/plugin/renderer/<renderer>.py`): finds the
fields with a `vays_options.renderer` that has a plugin, builds the context,
calls the plugin and writes its result into the agent's YAML document.

Renderers without a plugin are purely presentational in VAYS (or unknown):
their values are taken verbatim.

Raises: []
"""

import inspect
import logging
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml.comments import CommentedMap

from app import consts
from app.lib import locs
from app.lib import plugin
from app.lib import schema
from app.lib import yaml
from app.model.plg import MISSING, Error, Keep, RendererContext, Set, Unset

logger = logging.getLogger(__name__)


@dataclass
class State:
    """Carried over the validate/apply rounds of one tool call."""

    operation: str
    stored: Any
    secrets: dict[str, str]
    done: set[str] = field(default_factory=set)
    secrets_used: set[str] = field(default_factory=set)
    reports: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def error(self, loc: str, message: str) -> None:
        self.errors.append({"loc": loc, "message": message})


def plugin_controls(ui_schema: Any) -> list[tuple[schema.Control, Any]]:
    result = []
    for control in schema.controls(ui_schema):
        renderer = control.options.get("renderer")
        if not isinstance(renderer, str):
            continue
        module = plugin.find_module("renderer", renderer)
        if module is not None:
            result.append((control, module))
    return result


def describe(ui_schema: Any, json_schema: Any) -> list[dict]:
    """Notes for the agent about fields handled by plugins and VAYS hints."""
    notes = []
    for control in schema.controls(ui_schema):
        renderer = control.options.get("renderer")
        module = plugin.find_module("renderer", renderer) if isinstance(renderer, str) else None
        if module is not None:
            options = control.options.get("renderer_options") or {}
            node = schema.node(json_schema, control.pattern)
            describer = getattr(module, "describe", None)
            note = describer(options, node) if describer else "Handled by the server."
            notes.append({"loc": control.loc, "renderer": renderer, "note": note})
        elif "initial" in control.options:
            notes.append(
                {
                    "loc": control.loc,
                    "note": "Suggested value (VAYS shows it as placeholder or"
                    " preselection, it is only stored once the user picks it; set it"
                    " yourself if it fits): " + repr(control.options["initial"]),
                }
            )
    return notes


async def _prepare(module: Any, ctx: RendererContext):
    try:
        result = module.prepare(ctx)
        if inspect.isawaitable(result):
            result = await result
    except Exception as error:  # pylint: disable=broad-exception-caught
        logger.exception(f"Renderer plugin {ctx.renderer} failed at {ctx.loc}")
        return Error(f"The {ctx.renderer} plugin failed: {error}")
    return result


async def apply(state: State, doc: CommentedMap, ui_schema: Any, json_schema: Any) -> bool:
    """Run the plugins on `doc` (in place). Returns whether `doc` changed."""
    changed = False
    for control, module in plugin_controls(ui_schema):
        renderer = control.options["renderer"]
        pattern = list(control.pattern)
        stored_values = tuple(
            v
            for v in (locs.get(state.stored, p) for p in locs.expand(state.stored, pattern))
            if v is not MISSING
        )
        for tokens in locs.expand(doc, pattern):
            loc = locs.build(tokens)
            if loc in state.done:
                continue
            secret = state.secrets.get(loc)
            if secret is not None:
                if not getattr(module, "ACCEPTS_SECRET", False):
                    state.error(loc, "this field does not accept `secrets`")
                    state.done.add(loc)
                    continue
                state.secrets_used.add(loc)
            ctx = RendererContext(
                operation="create" if state.operation == "create" else "edit",
                loc=loc,
                pattern=control.loc,
                renderer=renderer,
                options=control.options.get("renderer_options") or {},
                schema=schema.node(json_schema, pattern),
                agent_value=yaml.plain(locs.get(doc, tokens)),
                current=locs.get(state.stored, tokens),
                stored_values=stored_values,
                secret=secret,
                reveal_secrets=consts.ENV.reveal_generated_secrets,
            )
            result = await _prepare(module, ctx)
            state.done.add(loc)
            if isinstance(result, Set):
                yaml.set_value(doc, tokens, result.value)
                changed = True
                if result.report:
                    state.reports.append({"loc": loc, "renderer": renderer, **result.report})
            elif isinstance(result, Unset):
                yaml.delete_value(doc, tokens)
                changed = True
            elif isinstance(result, Error):
                state.error(loc, result.message)
            elif not isinstance(result, Keep):
                state.error(loc, f"the {renderer} plugin returned {result!r}")
            elif ctx.generate_requested:
                state.error(loc, f'"{consts.MARKER_GENERATE}" is not supported here')
    return changed


def finish(state: State, doc: Any) -> None:
    """Final checks after the last round: stray secrets and markers."""
    for loc in sorted(set(state.secrets) - state.secrets_used):
        if not any(e["loc"] == loc for e in state.errors):
            state.error(loc, "`secrets` given, but there is no field here that accepts one")
    for loc in _find_markers(doc, []):
        if loc not in state.done:
            state.error(
                loc,
                f'"{consts.MARKER_GENERATE}" is only valid on fields the server generates'
                " (see the field notes)",
            )


def _find_markers(data: Any, prefix: list) -> list[str]:
    found = []
    if isinstance(data, dict):
        for key, value in data.items():
            found.extend(_find_markers(value, [*prefix, str(key)]))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            found.extend(_find_markers(value, [*prefix, str(index)]))
    elif data == consts.MARKER_GENERATE:
        found.append(locs.build(prefix))
    return found
