"""A small demo MCP server (stdio) for testing the MCP manager.

Run standalone:  python -m app.example_mcp_server
Register it in the app with command: .venv/bin/python  args: -m app.example_mcp_server
"""
from __future__ import annotations

import platform
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-tools")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the given text back."""
    return text


@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b


@mcp.tool()
def server_time() -> str:
    """Return the current server time and platform info."""
    return f"{time.strftime('%Y-%m-%d %H:%M:%S')} on {platform.platform()}"


if __name__ == "__main__":
    mcp.run()
