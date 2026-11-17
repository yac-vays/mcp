"""
Plugin loader, modeled on YAC's `app/lib/plugin.py`: every `*.py` file in
`app/plugin/<kind>/` is a plugin, keyed by its file stem. Additional plugin
roots (`YAC_MCP_PLUGIN_DIRS`, each with `<kind>/*.py` subdirs, e.g. mounted
from a ConfigMap) are loaded afterwards, so a later plugin with the same name
overrides an earlier one.

Raises: [app.model.err.PluginError]
"""

import glob
import logging
import pydoc
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from app import consts
from app.model.err import PluginError

logger = logging.getLogger(__name__)

_BUILTIN_ROOT = (Path(__file__).resolve().parent.parent / "plugin").as_posix()


def _roots() -> list[str]:
    return [_BUILTIN_ROOT, *consts.ENV.plugin_dirs]


@lru_cache(maxsize=None)
def get_modules(kind: str) -> dict[str, ModuleType]:
    modules: dict[str, ModuleType] = {}
    for root in _roots():
        kind_dir = f"{root.rstrip('/')}/{kind}"
        try:
            files = sorted(glob.glob(f"{kind_dir}/*.py"))
        except OSError as error:
            raise PluginError(f"Could not read {kind} plugin dir: {error}") from error
        for file in files:
            if Path(file).name.startswith("_"):
                continue
            name = Path(file).stem
            if name in modules:
                logger.warning(f"Plugin {file} overrides {kind} plugin {name}")
            logger.info(f"Loading plugin {file}")
            try:
                modules[name] = pydoc.importfile(file)
            except (pydoc.ErrorDuringImport, ImportError, OSError, SyntaxError) as error:
                raise PluginError(f"Could not import plugin {file}: {error}") from error
    return modules


def get_module(kind: str, name: str) -> ModuleType:
    module = get_modules(kind).get(name)
    if module is None:
        raise PluginError(f"There is no {kind} plugin named {name}")
    return module


def find_module(kind: str, name: str) -> ModuleType | None:
    return get_modules(kind).get(name)
