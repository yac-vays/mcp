from app.config import Settings

ENV = Settings()

MCP_PATH = "/mcp"
CONSENT_PATH = "/consent"
CALLBACK_PATH = "/callback"

# Sent with every upstream request; the YAC specs can declare it in
# `request.headers` (as `client`) so roles can restrict what agents may do.
CLIENT_HEADERS = {"YAC-Client": "mcp"}

# Marker an agent writes into a generated field to (re)generate its value.
MARKER_GENERATE = "~generate"

# Same patterns as YAC (app/consts.py) to fail early with a clear message.
NAME_PATTERN = r"^[a-zA-Z0-9_\-\.]{1,200}$"
SEARCH_PATTERN = r"^[a-zA-Z0-9_\-\. ]{0,200}$"
MSG_PATTERN = r"^[a-zäöüA-ZÄÖÜ0-9 @\(\)\"\.,_\/\-\r\n]{0,10000}$"
COMMIT_SUFFIX = "(via MCP)"

DEFAULT_YAML_COMMENT = "Automatically generated via MCP"
