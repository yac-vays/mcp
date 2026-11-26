"""The tools offered per allowed operations (YAC_MCP_ALLOW)."""

import pytest
from mcp.server.mcpserver import MCPServer

from app.lib import tools

READS = {"list_types", "list_entities", "read_entity", "new_entity", "validate", "read_logs"}


@pytest.mark.parametrize(
    "allow, writes",
    [
        ([], set()),
        (["actions"], {"run_action"}),
        (["create", "edit"], {"create", "edit"}),
        (["create", "edit", "actions"], {"create", "edit", "run_action"}),
        (["create", "edit", "delete", "actions"], {"create", "edit", "delete", "run_action"}),
    ],
)
async def test_tools_per_allow(env, allow, writes):
    env(allow=allow)
    mcp = MCPServer("yac", instructions=tools.instructions())
    tools.register(mcp)
    offered = {tool.name: tool for tool in await mcp.list_tools()}
    assert set(offered) == READS | writes
    # nothing offers the admin override
    for tool in offered.values():
        assert "force" not in tool.input_schema.get("properties", {})


def test_instructions_name_what_is_left_out(env):
    env(allow=[])
    assert "read-only" in tools.instructions()
    env(allow=["create", "edit"])
    note = tools.instructions().removeprefix(tools.INSTRUCTIONS)
    assert "delete, run actions" in note and "`run`" in note
    env(allow=["create", "edit", "delete", "actions"])
    assert tools.instructions() == tools.INSTRUCTIONS
