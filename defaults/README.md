# Wardex Defaults

This folder provides conservative default configuration files for both:

- agent runtimes (Claude Code hooks and MCP registration)
- application/server environments (`WARDEX_*` variables)

Start with these defaults, then loosen settings only if your use case requires it.

## Files

- `wardex.env.default`:
  Environment defaults for Wardex runtime behavior (includes localhost HTTP bind and optional Bearer auth token setting).
- `claude-settings.default.json`:
  Baseline Claude Code hook configuration for transaction interception.

## Quick Usage

```bash
cp defaults/wardex.env.default .env
cp defaults/claude-settings.default.json .claude/settings.json
```

Then register MCP with the same conservative mode:

```bash
claude mcp add wardex -e WARDEX_MODE=guardian npx @wardexai/mcp-server
```

If you enable HTTP transport, keep conservative network defaults:

```bash
export WARDEX_TRANSPORT=http
export WARDEX_PORT=3100
export WARDEX_HTTP_HOST=127.0.0.1
# Optional auth hardening:
# export WARDEX_HTTP_AUTH_TOKEN=replace-with-long-random-token
```
