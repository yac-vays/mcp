class MCPGatewayError(Exception):
    """
    Base error. The message is meant for the agent: it is returned as tool
    error, so it must explain what to do differently (never contain secrets).
    """


class ConfigError(MCPGatewayError):
    pass


class PluginError(MCPGatewayError):
    pass


class EnvelopeError(MCPGatewayError):
    pass


class InputError(MCPGatewayError):
    pass


class ReadOnlyError(MCPGatewayError):
    pass


class IdPError(MCPGatewayError):
    pass


class UpstreamError(MCPGatewayError):
    """An error response of a YAC backend."""

    def __init__(self, status: int, title: str, message: str):
        self.status = status
        self.title = title
        self.message = message
        super().__init__(f"{title} ({status}): {message}" if title else message)
