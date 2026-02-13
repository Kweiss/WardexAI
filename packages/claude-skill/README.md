# @wardexai/claude-skill

Claude Code skill bundle for Wardex transaction security workflows.

## What It Provides

- Skill instructions (`SKILL.md`)
- Command templates for common Wardex operations
- Hook scripts/templates for pre-transaction evaluation
- A conservative settings template for quick adoption

## Install

```bash
npm install @wardexai/claude-skill
```

## Contents

- `SKILL.md`
- `commands/`
- `hooks/`
- `settings-template.json`

## Quick Usage

```bash
cp node_modules/@wardexai/claude-skill/settings-template.json .claude/settings.json
claude mcp add wardex -e WARDEX_MODE=guardian npx @wardexai/mcp-server
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs/guides/claude-skill.md
