from typing import Literal

from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="yac_mcp_", env_nested_delimiter="__")

    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"
    format_plugin: str = "plain"

    # External base URL of this service (no trailing slash). It is the OAuth
    # issuer, and `{public_url}/mcp` is the MCP resource URL clients connect to.
    public_url: str = "http://localhost:8080"

    # VAYS-compatible config file (`backends[]`, `yamlComment`), read once at
    # startup. Usually the same content as the VAYS `config.json`.
    config: str = "/config.json"

    # The OIDC provider (the same one VAYS and YAC use) and this service's
    # confidential client there. The client_id must be accepted by every YAC
    # backend (`auth.oidc.client_ids`), since its id-tokens are forwarded.
    oidc_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_client_auth: Literal["client_secret_basic", "client_secret_post"] = (
        "client_secret_basic"
    )
    oidc_scope: str = "openid email"

    # Envelope keys as "kid:base64url(32 random bytes)". The first key
    # encrypts, all keys decrypt (rotation: prepend a new key, drop the old one
    # after `session_max_age`). Dropping all keys logs everybody out.
    keys: list[str] = []

    # The changes agents may make, in addition to reading (list, read,
    # validate, logs): any of "create", "edit", "delete" and "actions" (the
    # run_action tool and the `run` argument of the writes). Empty = read-only.
    # Actions the YAC specs force on a write run anyway (YAC decides). The
    # admin override (`force` on writes) is never offered.
    allow: list[Literal["create", "edit", "delete", "actions"]] = []

    # Return generated secrets (e.g. `age_secret` cleartexts) to the agent.
    # Anything returned ends up in the agent's transcript at the LLM provider.
    reveal_generated_secrets: bool = False

    # Additional plugin roots (each with `<kind>/*.py` subdirs), loaded after
    # the built-in ones; a later plugin with the same name wins.
    plugin_dirs: list[str] = []

    # Lifetimes (seconds) of the stateless OAuth envelopes.
    code_ttl: int = 60
    login_ttl: int = 600
    session_max_age: int = 30 * 86400
    consent_max_age: int = 90 * 86400

    # Client registration methods offered to MCP clients.
    client_registration: bool = True
    client_metadata_documents: bool = True
    # Allow client metadata document URLs resolving to private addresses.
    client_metadata_allow_private: bool = False

    upstream_timeout: float = 30.0

    # Timeout (seconds) of writes and actions: YAC commits, pushes and runs
    # the requested actions before it answers. A write that times out is
    # checked against the stored entity (see app.lib.entity).
    write_timeout: float = 300.0

    # Maximum size (characters) of a YAML document the gateway parses, like
    # YAC's `YAC_MAX_YAML_SIZE` (same default): the round-trip parser is slow
    # and runs on the event loop.
    max_yaml_size: int = 65536

    # Maximum size (characters) of a log content document handed to the agent
    # (the rest is cut off).
    max_log_content: int = 100_000

    # ATTENTION: development only! Disables the OAuth server and forwards the
    # bearer token of each MCP request unverified to the YAC backends.
    dev_token_passthrough: bool = False
