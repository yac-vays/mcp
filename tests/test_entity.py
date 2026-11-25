"""The tool operations against the fake YAC backend."""

import json

import httpx

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
        await entity.edit(
            client, "host", "web01", STORED.replace("alice", "erin"), None, token, None, "", []
        )


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


async def test_edit_without_changes_commits_nothing(fake, client):
    """YAC refuses a write that changes nothing: the gateway does not send it."""
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    result = await entity.edit(client, "host", "web01", STORED, None, token, None, "", [])
    assert result == {"committed": False, "unchanged": True, "hint": entity.UNCHANGED_HINT}
    # A patch re-sending stored values is no change either (like a YAC patch).
    result = await entity.edit(
        client, "host", "web01", None, {"owner": "alice"}, token, None, "", []
    )
    assert result["unchanged"] and not fake.commits
    result = await entity.validate(client, "host", "edit", "web01", STORED, None, token, None)
    assert result["valid"] and result["unchanged"]
    # A comment-only change is a change (YAC requires `cln` for it).
    result = await entity.edit(
        client, "host", "web01", STORED.replace("hand written", "by hand"), None, token, None,
        "", [],
    )
    assert result["committed"], result


async def test_after_action_warning_is_reported(fake, client):
    fake.after_action_warning = "The action deploy failed after the commit"
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    await entity.edit(client, "host", "web01", None, {"owner": "erin"}, token, None, "", ["deploy"])
    assert "The action deploy failed after the commit" in client.warnings


async def test_logs_and_content(fake, client, env):
    (typ,) = await entity.list_types(client)
    assert typ["logs"] == [
        {"name": "facts", "title": "Facts", "description": "Gathered facts", "renderer": "document"}
    ]
    logs = await entity.read_logs(client, "host", "web01", None)
    assert logs["logs"][0]["has_content"]
    content = await entity.read_logs(client, "host", "web01", "facts")
    assert content == {"log": "facts", "time": "2026-11-25", "content": fake.log_content}
    env(max_log_content=5)
    content = await entity.read_logs(client, "host", "web01", "facts")
    assert content["content"] == fake.log_content[:5] and "truncated" in content
    with pytest.raises(InputError, match="log"):
        await entity.read_logs(client, "host", "web01", "../x")


@pytest.mark.parametrize(
    "text, message",
    [
        ("%YAML 1.1\n---\na: yes\n", "directives"),
        ("a: &a [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]\n"
         + "".join(f"{c}: &{c} [{', '.join([f'*{p}'] * 10)}]\n"
                   for p, c in zip("abcde", "bcdef")), "aliases are expanded"),
        ("a: " + "[" * 5000 + "]" * 5000 + "\n", "nested too deeply"),
        ("a: 0x_\n", "not valid"),
    ],
)
async def test_yaml_is_bounded_like_in_yac(fake, client, text, message):
    with pytest.raises(InputError, match=message):
        await entity.validate(client, "host", "create", "web09", text, None, None, None)
    assert not any(r.url.path == "/validate" for r in fake.requests)


async def test_yaml_size_limit(fake, client, env):
    env(max_yaml_size=100)
    with pytest.raises(InputError, match="too big"):
        await entity.validate(client, "host", "create", "web09", "a: " + "x" * 200, None, None, None)


async def test_read_entity_validates_as_edit(fake, client):
    """Limit usages and the edit schema, like VAYS' edit mode (YAC measures no
    limits for a read); a user without `edt` gets the read schema."""
    fake.usages = [{"title": "Quota", "path": "#/quota", "usage": 3, "max": 5, "ok": True}]
    result = await entity.read_entity(client, "host", "web01")
    assert result["usages"] == fake.usages
    body = json.loads(fake.requests[-1].content)
    assert body["operation"] == "edit" and body["entity"]["yaml_new"] == STORED
    fake.perms = ["see"]
    result = await entity.read_entity(client, "host", "web01")
    assert result["usages"] == [] and result["perms"] == ["see"]
    assert json.loads(fake.requests[-1].content)["operation"] == "read"


LOST = [httpx.ReadTimeout(""), httpx.RemoteProtocolError("Server disconnected"), 504]


@pytest.mark.parametrize("failure", LOST)
async def test_edit_with_lost_answer_is_checked(fake, client, failure):
    """A write whose answer got lost: the stored entity decides the result."""
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    fake.fail_after_write = failure
    result = await entity.edit(client, "host", "web01", None, {"owner": "erin"}, token, None, "", [])
    assert result["committed"] and "owner: erin" in fake.files["web01"]
    assert any("the change is stored" in w for w in client.warnings)


@pytest.mark.parametrize("failure", LOST)
async def test_edit_not_stored_can_be_retried(fake, client, failure):
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    fake.fail_before_write = failure
    with pytest.raises(InputError, match="not stored, you can try again"):
        await entity.edit(client, "host", "web01", None, {"owner": "erin"}, token, None, "", [])
    result = await entity.edit(client, "host", "web01", None, {"owner": "erin"}, token, None, "", [])
    assert result["committed"] and len(fake.commits) == 1


async def test_comment_only_edit_with_lost_answer(fake, client):
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    fake.fail_after_write = httpx.ReadTimeout("")
    changed = STORED.replace("hand written", "by hand")
    result = await entity.edit(client, "host", "web01", changed, None, token, None, "", [])
    assert result["committed"] and "# by hand" in fake.files["web01"]


async def test_create_and_delete_with_lost_answer(fake, client):
    yaml_text = "owner: carol\nusers: []\n"
    fake.fail_after_write = 504
    result = await entity.create(client, "host", "web03", yaml_text, None, "", [])
    assert result["committed"] and "web03" in fake.files
    fake.fail_before_write = httpx.ReadTimeout("")
    with pytest.raises(InputError, match="not created, you can try again"):
        await entity.create(client, "host", "web04", yaml_text, None, "", [])
    fake.fail_after_write = httpx.ReadTimeout("")
    assert await entity.delete(client, "host", "web03", "", []) == {"deleted": "web03"}
    fake.fail_before_write = 504
    with pytest.raises(InputError, match="not deleted"):
        await entity.delete(client, "host", "web01", "", [])


async def test_unreachable_backend_is_not_uncertain(fake, client):
    token = (await entity.read_entity(client, "host", "web01"))["edit_token"]
    fake.fail_before_write = httpx.ConnectError("refused")
    with pytest.raises(UpstreamError, match="unreachable") as raised:
        await entity.edit(client, "host", "web01", None, {"owner": "erin"}, token, None, "", [])
    assert not raised.value.uncertain
    fake.fail_after_write = httpx.ReadTimeout("")
    with pytest.raises(InputError, match="may have run"):
        await entity.run_action(client, "host", "web01", "deploy")
