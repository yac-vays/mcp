"""The plugin loader and the generic contract test over all renderer plugins."""

import pytest

from app.lib import plugin
from app.model.err import PluginError
from app.model.plg import RendererContext

BASE = {"operation": "create", "loc": "#/field", "pattern": "#/field", "options": {}, "schema": {}}


def _vectors():
    for name, module in sorted(plugin.get_modules("renderer").items()):
        for index, (kwargs, check) in enumerate(getattr(module, "TEST_VECTORS", [])):
            yield pytest.param(name, module, kwargs, check, id=f"{name}-{index}")


def test_builtin_plugins_loaded():
    assert {"age_secret", "password", "random_string"} <= set(plugin.get_modules("renderer"))
    assert plugin.find_module("renderer", "ssh_key") is None
    with pytest.raises(PluginError):
        plugin.get_module("renderer", "nope")


@pytest.mark.parametrize("name,module,kwargs,check", list(_vectors()))
async def test_plugin_vectors(name, module, kwargs, check):
    ctx = RendererContext(**{**BASE, "renderer": name, **kwargs})
    result = module.prepare(ctx)
    if hasattr(result, "__await__"):
        result = await result
    assert check(result), f"{name}: unexpected result {result!r} for {kwargs}"


def test_every_plugin_has_vectors_and_describe():
    for name, module in plugin.get_modules("renderer").items():
        assert getattr(module, "TEST_VECTORS", None), f"{name} has no TEST_VECTORS"
        assert isinstance(module.describe({}, {}), str)


def test_extra_plugin_dir_overrides(tmp_path, env):
    (tmp_path / "renderer").mkdir()
    (tmp_path / "renderer" / "random_string.py").write_text(
        "from app.model.plg import Set\n"
        "def prepare(ctx):\n    return Set('fixed')\n"
        "TEST_VECTORS = [({}, lambda r: r.value == 'fixed')]\n"
    )
    (tmp_path / "renderer" / "pin.py").write_text(
        "from app.model.plg import Keep\ndef prepare(ctx):\n    return Keep()\n"
    )
    env(plugin_dirs=[str(tmp_path)])
    plugin.get_modules.cache_clear()
    try:
        modules = plugin.get_modules("renderer")
        assert modules["random_string"].prepare(None).value == "fixed"
        assert "pin" in modules and "age_secret" in modules
    finally:
        plugin.get_modules.cache_clear()


def test_sha512_crypt_matches_vays_and_spec():
    # Test vector from https://www.akkadia.org/drepper/SHA-crypt.txt, which is
    # also what VAYS' hash_sha512("Hello world!", "saltstring") yields.
    # pylint: disable=import-outside-toplevel
    from passlib.hash import sha512_crypt

    assert sha512_crypt.using(rounds=5000, salt="saltstring").hash("Hello world!") == (
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJ"
        "uesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    )
