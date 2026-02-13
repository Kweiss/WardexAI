# @wardexai/mcp-server

Model Context Protocol server for exposing Wardex security tools to MCP clients.

## What It Provides

- MCP tools for transaction evaluation and policy-aware checks
- Integration point for Claude Code and other MCP-compatible clients
- `stdio` and HTTP transports
- Conservative HTTP defaults: localhost bind (`127.0.0.1`) and optional Bearer auth

## Install

```bash
npm install @wardexai/mcp-server
```

## Run

```bash
npx @wardexai/mcp-server
```

HTTP transport (remote agents / multi-client):

```bash
WARDEX_TRANSPORT=http \
WARDEX_PORT=3100 \
WARDEX_HTTP_HOST=127.0.0.1 \
npx @wardexai/mcp-server
```

Optional auth hardening for HTTP MCP endpoints:

```bash
WARDEX_HTTP_AUTH_TOKEN=replace-with-long-random-token npx @wardexai/mcp-server --transport http
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs/guides/mcp-server.md
