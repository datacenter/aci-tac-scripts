"""ACI Model Docs MCP Server."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

from aci_model_docs.apic_client import ApicClient  # noqa: E402


@dataclass
class AppContext:
    client: ApicClient


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage the APIC client lifecycle."""
    client = ApicClient()
    try:
        await client.login()
        yield AppContext(client=client)
    finally:
        await client.close()


mcp = FastMCP(
    "ACI Model Docs",
    instructions="Look up Cisco ACI object model documentation from a live APIC",
    lifespan=app_lifespan,
)

# Import and register tools
from aci_model_docs.tools.lookup_class import lookup_class  # noqa: E402
from aci_model_docs.tools.list_classes import list_classes  # noqa: E402
from aci_model_docs.tools.search_classes import search_classes  # noqa: E402

mcp.tool()(lookup_class)
mcp.tool()(list_classes)
mcp.tool()(search_classes)


if __name__ == "__main__":
    mcp.run()
