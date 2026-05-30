# ACI Model Docs MCP Server

An MCP (Model Context Protocol) server that exposes Cisco ACI object model documentation from a live APIC. It lets an AI assistant look up class metadata, list available managed object classes, and search by keyword — all sourced directly from your APIC.

## Tools

| Tool | Description |
|---|---|
| `lookup_class` | Fetch full docs for an ACI class: properties, DN/RN format, parent/child relationships, REST endpoint |
| `list_classes` | List available ACI managed object classes, optionally filtered by package prefix (e.g. `fv`, `vz`) |
| `search_classes` | Search class names, labels, and descriptions by keyword (e.g. `bridge domain`, `contract`) |

## Prerequisites

- Python 3.11+
- Access to a Cisco APIC (URL + credentials)
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`

## Setup

### 1. Clone and enter the project

```bash
git clone <repo-url>
cd aci-model-docs
```

### 2. Create a virtual environment and install dependencies

With `uv` (recommended):

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

Or with plain `pip`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Configure environment variables

Copy the example file and fill in your APIC credentials:

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
APIC_URL=https://<apic-ip-or-hostname>
APIC_USER=admin
APIC_PASS=your_password_here

# Authentication domain (default: fallback)
APIC_LOGIN_DOMAIN=fallback

# Optional: comma-separated package prefixes to limit class listings
# Leave empty or unset to show all packages
APIC_PACKAGES=fv,vz,l3ext,infra,fabric
```

> **Note:** The server uses cookie-based authentication and will automatically re-authenticate if the session expires. TLS verification is disabled by default to accommodate self-signed APIC certificates.

### 4. Verify the server starts

```bash
.venv/bin/python -m aci_model_docs.server
```

The process will block waiting on stdin — that is correct for an stdio MCP server. If it does not print a traceback and does not exit, startup and APIC login succeeded. Press `Ctrl+C` to stop.

> **Note:** `mcp dev` (the browser inspector) is incompatible with this server due to how the MCP CLI loads files internally. Use `python -m` for manual verification.

## Connecting to VS Code (GitHub Copilot)

Add the server to your VS Code MCP configuration (`.vscode/mcp.json` or user settings):

```json
{
  "servers": {
    "aci-model-docs": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "aci_model_docs/server.py"],
      "cwd": "/path/to/aci-model-docs"
    }
  }
}
```

Credentials are read from the `.env` file at the `cwd` path — do not put secrets in `mcp.json`.

## Connecting to Claude Desktop

Add the following to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "aci-model-docs": {
      "command": "uv",
      "args": ["run", "aci_model_docs/server.py"],
      "cwd": "/path/to/aci-model-docs"
    }
  }
}
```

Credentials are read from the `.env` file at `cwd`.

## Project Structure

```
aci-model-docs/
├── aci_model_docs/
│   ├── server.py          # FastMCP server entrypoint
│   ├── apic_client.py     # Async APIC REST client (auth + metadata endpoints)
│   └── tools/
│       ├── lookup_class.py   # lookup_class tool
│       ├── list_classes.py   # list_classes tool
│       └── search_classes.py # search_classes tool
├── .env.example           # Environment variable template
├── pyproject.toml
└── README.md
```
