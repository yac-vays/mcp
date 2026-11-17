import json
from pathlib import Path

import pyrage
from passlib.hash import sha512_crypt

from app.lib import renderers
from app.lib import schema
from app.lib import yaml as yamllib

SCHEMAS = json.loads((Path(__file__).parent / "fixtures" / "schemas.json").read_text())
UI, JS = SCHEMAS["ui_schema"], SCHEMAS["json_schema"]
KEY = pyrage.x25519.Identity.generate()


def _schemas_with_key():
    ui = json.loads(json.dumps(UI).replace("age1abc", str(KEY.to_public())))
    return ui, JS


async def _run(operation, text, stored=None, secrets=None):
    ui, js = _schemas_with_key()
    doc = yamllib.load(text)
    schema.apply_defaults(doc, js)
    state = renderers.State(operation=operation, stored=stored, secrets=secrets or {})
    await renderers.apply(state, doc, ui, js)
    renderers.finish(state, doc)
    return doc, state


async def test_create_generates_and_hashes():
    text = "# keep me\nowner: alice  # inline\nusers:\n  - name: bob\n"
    doc, state = await _run("create", text, secrets={"#/users/0/pw": "hunter2"})
    assert not state.errors, state.errors
    assert len(doc["machine_id"]) == 16 and int(doc["machine_id"], 16) >= 0
    assert len(doc["net"]["token"]) == 32 and doc["net"]["os"] == "linux"
    assert pyrage.decrypt(doc["secret"].encode(), [KEY]).decode().isalnum()
    assert sha512_crypt.verify("hunter2", doc["users"][0]["pw"])
    dumped = yamllib.dump(doc)
    assert "# keep me" in dumped and "# inline" in dumped and "hunter2" not in dumped
    reported = {r["loc"]: r for r in state.reports}
    assert reported["#/secret"]["generated"] and "secret" not in reported["#/secret"]
    assert reported["#/machine_id"]["value"] == doc["machine_id"]


async def test_edit_keeps_stored_values_and_rejects_cleartext():
    stored_text = (
        "owner: a\nsecret: CIPHER\nmachine_id: abc\nusers:\n  - name: x\n    pw: $6$s$h\n"
    )
    stored = yamllib.plain(yamllib.load(stored_text))
    # agent dropped secret + machine_id, kept the hash, wrote a cleartext elsewhere
    doc, state = await _run(
        "edit", "owner: b\nusers:\n  - name: x\n    pw: $6$s$h\n  - name: y\n    pw: plain\n", stored
    )
    assert doc["secret"] == "CIPHER" and doc["machine_id"] == "abc"
    assert doc["users"][0]["pw"] == "$6$s$h"
    assert [e["loc"] for e in state.errors] == ["#/users/1/pw"]


async def test_markers_and_stray_secrets():
    stored = {"secret": "CIPHER", "machine_id": "abc"}
    doc, state = await _run(
        "edit",
        "owner: ~generate\nsecret: ~generate\nmachine_id: ~generate\n",
        stored,
        secrets={"#/owner": "x", "#/machine_id": "y"},
    )
    assert doc["secret"].startswith("-----BEGIN AGE") and doc["machine_id"] != "abc"
    errors = {e["loc"]: e["message"] for e in state.errors}
    assert "#/machine_id" in errors and "does not accept" in errors["#/machine_id"]
    assert "#/owner" in errors


async def test_unknown_renderers_pass_through():
    ui = {"type": "Control", "scope": "#/properties/key", "options": {"renderer": "ssh_key"}}
    doc = yamllib.load("key: ssh-ed25519 AAAA\n")
    state = renderers.State(operation="create", stored=None, secrets={})
    assert not await renderers.apply(state, doc, ui, {})
    assert doc["key"] == "ssh-ed25519 AAAA" and not state.errors


def test_describe_notes():
    notes = {n["loc"]: n for n in renderers.describe(UI, JS)}
    assert notes["#/secret"]["renderer"] == "age_secret"
    assert notes["#/users/*/pw"]["renderer"] == "password"
    assert "windows" in notes["#/net/os"]["note"]
    assert "#/owner" not in notes
