"""Shared HTTP client configuration for check-in plugin requests."""

import aiohttp


def create_client_session() -> aiohttp.ClientSession:
    """Create an HTTP session with the plugin's shared request settings."""
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False),
        trust_env=True,
    )
