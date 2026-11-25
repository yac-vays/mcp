import json
from pathlib import Path

from app.lib import locs
from app.lib import schema
from app.lib.locs import ITEMS

SCHEMAS = json.loads((Path(__file__).parent / "fixtures" / "schemas.json").read_text())


def test_controls_from_yac_ui_schema():
    found = {c.pattern: c.options for c in schema.controls(SCHEMAS["ui_schema"])}
    assert found[("secret",)]["renderer"] == "age_secret"
    assert found[("machine_id",)]["renderer_options"] == {"format": "hex", "length": 16}
    assert found[("net", "token")]["renderer"] == "random_string"
    assert found[("net", "os")]["initial"] == "windows"
    assert found[("users", ITEMS, "pw")]["renderer"] == "password"


def test_node():
    js = SCHEMAS["json_schema"]
    assert schema.node(js, ("net", "os"))["default"] == "linux"
    assert schema.node(js, ("users", ITEMS, "pw"))["type"] == "string"
    assert schema.node(js, ("users", "3", "pw"))["type"] == "string"
    assert schema.node(js, ("nope", "x")) == {}


def test_apply_defaults_like_ajv():
    data: dict = {}
    filled = schema.apply_defaults(data, SCHEMAS["json_schema"])
    # net defaults to {} and then gets its own defaults (useDefaults semantics)
    assert data == {"net": {"os": "linux"}, "users": []}
    assert set(filled) == {"#/net", "#/net/os", "#/users"}
    data = {"net": {"os": "windows"}, "users": [{"name": "x"}]}
    assert schema.apply_defaults(data, SCHEMAS["json_schema"]) == []
    assert data["net"]["os"] == "windows"


def test_trim_and_all_errors():
    trimmed = schema.trim({"type": "object", "vays_options": {}, "properties": {"a": {"vays_category": "x"}}})
    assert trimmed == {"type": "object", "properties": {"a": {}}}
    errors = schema.all_errors(SCHEMAS["json_schema"], {"owner": 1, "users": [{"name": "x"}]})
    messages = {(e["loc"], e["message"]) for e in errors}
    assert ("#/owner", "1 is not of type 'string'") in messages
    assert any(loc == "#/users/0" and "pw" in msg for loc, msg in messages)
    assert any(loc == "#" and "machine_id" in msg for loc, msg in messages)


def test_locs():
    assert locs.parse("#/a~1b/0/c~0d") == ["a/b", "0", "c~d"]
    assert locs.build(["a/b", "0", "c~d"]) == "#/a~1b/0/c~0d"
    data = {"u": [{"p": 1}, {"p": 2}], "o": {}}
    assert locs.expand(data, ["u", ITEMS, "p"]) == [["u", "0", "p"], ["u", "1", "p"]]
    assert locs.expand(data, ["missing", ITEMS, "p"]) == []
    assert locs.expand(data, ["o", "x"]) == [["o", "x"]]
    assert locs.get(data, ["u", "1", "p"]) == 2


def test_refresh_defaults_like_vays():
    """Values the gateway filled in follow changed defaults, others stay."""
    data = {"os": "ubuntu", "version": "24.04", "owner": "me", "net": {"vlan": 1}}
    filled = {"#/version": "24.04", "#/owner": "you", "#/net": {"vlan": 1}, "#/gone": 1}
    json_schema = {"properties": {
        "version": {"default": "26.04"},  # changed default: follows
        "owner": {"default": "them"},  # changed since filled in: stays
        "net": {"properties": {"vlan": {"type": "integer"}}},  # default removed: removed
    }}
    changed = schema.refresh_defaults(data, json_schema, filled)
    assert sorted(changed) == ["#/net", "#/version"]
    assert data == {"os": "ubuntu", "version": "26.04", "owner": "me"}
    assert filled == {"#/version": "26.04"}


def test_node_numeric_property_names():
    json_schema = {"properties": {"ports": {"properties": {"0": {"default": 1}}}}}
    assert schema.node(json_schema, ["ports", "0"]) == {"default": 1}
    assert schema.node({"items": {"type": "string"}}, ["0"]) == {"type": "string"}
