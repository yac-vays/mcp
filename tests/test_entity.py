"""The tool operations against the fake YAC backend."""

import json

import pyrage
import pytest
import respx
from passlib.hash import sha512_crypt

from app.lib import backends
from app.lib import entity
from app.lib import yaml as yamllib
from app.lib.yac import Yac
from app.model.err import InputError, ReadOnlyError, UpstreamError

from tests.fake_yac import FakeYac

KEY = pyrage.x25519.Identity.generate()
STORED = "---\n# hand written\nowner: alice\nsecret: CIPHER\nmachine_id: 0123456789abcdef\n" \
    "net:\n  token: tok\n  os: linux\nusers:\n  - name: bob\n    pw: $6$salt$hash\n"


@pytest.fixture
def fake():
    with respx.mock(assert_all_called=False) as router:
        yac = FakeYac({"web01": STORED}).mock(router)
        yac.schemas = json.loads(
            json.dumps(yac.schemas).replace("age1abc", str(KEY.to_public()))
        )
        yield yac


@pytest.fixture
def client():
    return Yac(backends.get("hosts"), "ID-TOKEN")


async def test_requests_carry_user_token_and_client_header(fake, client):
    await entity.list_types(client)
    request = fake.requests[-1]
    assert request.headers["authorization"] == "Bearer ID-TOKEN"
    assert request.headers["yac-client"] == "mcp"


async def test_list_types_trimmed(fake, client):
    (typ,) = await entity.list_types(client)
    assert typ["name"] == "host" and typ["actions"] == [
        {"name": "deploy", "title": "Deploy", "description": "", "dangerous": False}
    ]
    assert "icon" not in json.dumps(typ) and "favorites" not in typ


async def test_read_entity(fake, client):
    result = await entity.read_entity(client, "host", "web01")
    assert result["yaml"] == STORED
    assert "vays" not in json.dumps(result["json_schema"])
    assert {n["loc"] for n in result["field_notes"]} >= {"#/secret", "#/users/*/pw"}
    assert result["edit_token"].count(".") == 4


async def test_new_entity_seed(fake, client):
    result = await entity.new_entity(client, "host")
    assert result["yaml"].startswith("---\n# Managed via the test portal\n")
    assert yamllib.plain(yamllib.load(result["yaml"])) == {"net": {"os": "linux"}, "users": []}
    assert result["name"]["name_pattern"]


async def test_create_full_flow(fake, client):
    text = "owner: carol\nusers:\n  - name: dave\n"
    result = await entity.create(
        client, "host", "web02", text, {"#/users/0/pw": "pw1"}, "New host", []
    )
    assert result["committed"], result
    (commit,) = fake.commits
    assert commit["msg"] == "New host\n\n(via MCP)"
    stored = yamllib.plain(yamllib.load(commit["yaml"]))
    assert stored["owner"] == "carol" and stored["net"] == {"token": stored["net"]["token"], "os": "linux"}
    assert sha512_crypt.verify("pw1", stored["users"][0]["pw"])
    assert pyrage.decrypt(stored["secret"].encode(), [KEY])
    assert "pw1" not in json.dumps(result)
    assert {r["loc"] for r in result["generated"]} == {
        "#/secret", "#/machine_id", "#/net/token", "#/users/0/pw"
    }


async def test_create_without_name(fake, client):
    result = await entity.create(client, "host", None, "owner: x\nusers: []\n", None, "", [])
    assert not result["committed"]
    assert result["errors"] == [
        {"loc": None, "message": "The entity.name must be set for this operation"}
    ]


async def test_create_invalid_commits_nothing(fake, client):
    result = await entity.create(client, "host", "web03", "owner: 5\n", None, "", [])
    assert not result["committed"] and not fake.commits
    assert any(e["loc"] == "#/owner" for e in result["errors"])


async def test_validate_dry_run_hides_values(fake, client):
    result = await entity.validate(
        client, "host", "create", "web09", "owner: x\nusers: []\n", None, None, None
    )
    assert result["valid"], result
    assert all("value" not in r for r in result["would_generate"])


async def test_edit_with_data_patch_and_token(fake, client):
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    result = await entity.edit(
        client, "host", "web01", None, {"owner": "erin"}, token, {"#/users/0/pw": "new"}, "", []
    )
    assert result["committed"], result
    new = fake.files["web01"]
    assert "# hand written" in new and "owner: erin" in new and "secret: CIPHER" in new
    assert sha512_crypt.verify("new", yamllib.plain(yamllib.load(new))["users"][0]["pw"])
    assert fake.commits[-1]["msg"] == "(via MCP)"


async def test_edit_conflict(fake, client):
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    fake.files["web01"] = STORED.replace("alice", "zoe")
    with pytest.raises(InputError, match="changed in the meantime"):
        await entity.edit(client, "host", "web01", STORED, None, token, None, "", [])


async def test_edit_token_for_other_entity(fake, client):
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    fake.files["web02"] = STORED
    with pytest.raises(InputError, match="another entity"):
        await entity.edit(client, "host", "web02", STORED, None, token, None, "", [])


async def test_guards(fake, client, env):
    with pytest.raises(InputError, match="message"):
        entity.commit_message("no: colons allowed")
    with pytest.raises(InputError):
        await entity.create(client, "host", "bad name", "", None, "", [])
    with pytest.raises(InputError, match="either"):
        await entity.edit(client, "host", "web01", None, None, None, None, "", [])
    env(read_only=True)
    with pytest.raises(ReadOnlyError):
        await entity.delete(client, "host", "web01", "", [])


async def test_upstream_errors(fake, client):
    with pytest.raises(UpstreamError, match="Not Found"):
        await entity.read_entity(client, "host", "nope")
    with pytest.raises(UpstreamError, match="unreachable"):
        await entity.list_types(Yac(backends.get("down"), "t"))
