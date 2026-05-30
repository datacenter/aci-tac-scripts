# ACI Model Docs — Agent Instructions

## Purpose

MCP server that exposes Cisco ACI object model documentation from a live APIC.
Tools: `lookup_class`, `list_classes`, `search_classes`.

## Critical: `.env` is required before the server will start

The `.vscode/mcp.json` passes **no environment variables**. The server reads credentials exclusively from a `.env` file in the project root via `python-dotenv`. If `.env` is absent, the server crashes immediately with:

```
KeyError: 'APIC_URL'
```

**Before doing anything else**, create `.env` from the template:

```bash
cp .env.example .env
```

Then populate all required fields (see Environment Variables below).

## Prerequisites

Verify before attempting to start:

```bash
uv --version        # must be present — mcp.json uses "command": "uv"
python --version    # must be >= 3.11
```

Install `uv` if missing:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Setup Sequence

Run these in order from the project root:

```bash
# 1. Create and populate .env (see Environment Variables section)
cp .env.example .env
# → edit .env with real values

# 2. Install dependencies
uv sync

# 3. Verify APIC is reachable before starting (avoids silent startup failure)
curl -sk -o /dev/null -w "%{http_code}" "$APIC_URL/api/aaaLogin.json"
# → expect 200 or 405; anything else means the URL or network is wrong

# 4. Start the server
uv run aci_model_docs/server.py
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `APIC_URL` | Yes | Base URL of the APIC, e.g. `https://10.0.0.1` — no trailing slash |
| `APIC_USER` | Yes | APIC username |
| `APIC_PASS` | Yes | APIC password |
| `APIC_LOGIN_DOMAIN` | No | AAA login domain; defaults to `fallback`. For remote AAA (LDAP/TACACS) set to the domain name configured on the APIC |
| `APIC_PACKAGES` | No | Comma-separated package prefixes to limit `list_classes` output (e.g. `fv,vz,l3ext`). Leave unset to return all packages |

The login payload encodes the domain as `apic#DOMAIN\\username`. If login fails with 401, verify `APIC_LOGIN_DOMAIN` matches the AAA domain on the APIC.

## Expected Startup Output

On successful start, the server logs to stderr and becomes silent (it's stdio-based):

```
INFO:     Started server process
INFO:     Waiting for application startup
INFO:     Application startup complete
```

The process then blocks — this is correct. The MCP host (VS Code / Claude Desktop) connects over stdio.

`InsecureRequestWarning` lines from urllib3 are **expected and harmless** — TLS verification is intentionally disabled for self-signed APIC certificates.

## Common Errors and Fixes

| Symptom | Cause | Fix |
|---|---|---|
| `KeyError: 'APIC_URL'` | `.env` file missing or not in project root | `cp .env.example .env` and populate |
| `ConnectError` / `RemoteDisconnected` | Wrong `APIC_URL` or network unreachable | Verify URL with `curl -sk $APIC_URL` |
| `HTTPStatusError 401` | Wrong credentials or wrong `APIC_LOGIN_DOMAIN` | Check username/password; try `APIC_LOGIN_DOMAIN=fallback` |
| `HTTPStatusError 404` on `/doc/jsonmeta/` | APIC firmware too old or documentation app not installed | Metadata tools will return an error; `list_classes` falls back to the built-in known-classes list |
| `uv: command not found` | `uv` not installed | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Server starts but VS Code doesn't connect | `mcp.json` `cwd` wrong or `.env` not found by server | Ensure `cwd` is the project root where `.env` lives |

## VS Code Integration

The `.vscode/mcp.json` is already configured. After populating `.env`, reload VS Code — the server starts automatically when a tool is invoked.

> **Important:** VS Code only reads `.vscode/mcp.json` from the **workspace root**. If you open a parent folder (e.g. `mcp_dev/`) instead of `aci-model-docs/` directly, the config inside `aci-model-docs/.vscode/` will be ignored. Either open `aci-model-docs/` as the workspace root, or place an `mcp.json` at the parent's `.vscode/` with `"cwd": "${workspaceFolder}/aci-model-docs"`.

To verify the server starts cleanly before wiring it into VS Code:

```bash
.venv/bin/python -m aci_model_docs.server
```

The process will block waiting for stdin — that is correct for a stdio MCP server. If it does not print a traceback and does not exit, the server (and APIC login) started successfully. Press `Ctrl+C` to stop.

> **Note:** `mcp dev` (the browser-based inspector) is incompatible with this server. It loads the file via `importlib.util.spec_from_file_location` which breaks the `@dataclass` decorator — the module is not registered under its real name in `sys.modules`. Use `python -m aci_model_docs.server` instead.
