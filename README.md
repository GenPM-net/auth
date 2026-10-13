# @core/auth

[![genpm](https://api.genpm.net/v1/badge/@core/auth.svg)](https://genpm.net/p/@core/auth) ![license](https://img.shields.io/badge/license-MIT-blue)

> Sessions + OAuth (GitHub, Google) with Drizzle, for Hono and Next.js

A [GenPM](https://genpm.net) module: **source code + AI rules + MCP config**, injected into your project instead of hidden in `node_modules`. The code lands in `src/lib/auth`, pinned to a verified commit, and you own it.

## Install

```bash
genpm add @core/auth
```

No genpm yet? `curl -fsSL https://genpm.net/install.sh | sh` (macOS/Linux), `irm https://genpm.net/install.ps1 | iex` (Windows), or one-off with `npx @genpm-net/cli add @core/auth`.

Or let your AI agent do it: run `genpm mcp setup` once, then ask *"add @core/auth with genpm"* in Claude Code, Cursor, VS Code, Windsurf, Codex or Gemini CLI. It shows you a dry-run plan before writing anything.

## What it does

Cookie sessions (random token, only its SHA-256 stored, 30-day sliding expiry, rotation) and OAuth login with GitHub
and Google via `arctic`. Tables: `users`, `auth_sessions`, `oauth_accounts`. No roles or permissions (out of scope:
build them in your app on top of `users.id`). No passwords.

## At a glance

- **GenPM dependencies** (installed with it): [@core/db](https://genpm.net/p/@core/db)
- **npm dependencies** (proposed, never installed without asking): `arctic`, `@oslojs/crypto`, `@oslojs/encoding`
- **Environment variables** (added to `.env.example`): `AUTH_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- **AI rules**: [`AGENTS.md`](AGENTS.md), loaded by your agent only when it works in `src/lib/auth`

## Security

GenPM installs a 40-character commit SHA (never a branch), verifies an Ed25519-signed manifest, never runs install scripts and scans AI rules for prompt injection. Details: [genpm.net/docs/security](https://genpm.net/docs/security).

## License

MIT — see [LICENSE](LICENSE). Browse the full catalog at [genpm.net](https://genpm.net).
