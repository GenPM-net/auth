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

## Setup

After `genpm add`, follow these steps (your AI agent finds the same steps in `src/lib/auth/AGENTS.md` and can do them for you):

1. Env: `AUTH_SECRET` (≥ 32 random chars, e.g. `openssl rand -base64 32`), `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.
   Optional Google: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`. Providers without both vars are disabled.
2. OAuth app callback URL: `<origin>/auth/callback/github` (and `/auth/callback/google`).
3. Generate and apply migrations (see `src/lib/db/AGENTS.md`).
4. Hono:
   ```ts
   import { authRoutes, requireUser, sessionMiddleware } from './lib/auth/adapters/hono.ts';
   app.use(sessionMiddleware);
   app.route('/auth', authRoutes());
   app.get('/api/me', requireUser, (c) => c.json(c.get('user')));
   ```
   Next.js (App Router): create `app/auth/login/[provider]/route.ts` with `export { loginRoute as GET } from '@/lib/auth/adapters/next'`,
   the same for `callback/[provider]` (`callbackRoute`) and `app/auth/logout/route.ts` (`logoutRoute as POST`).
   In Server Components: `const user = await getUser(await cookies())`.
   Delete the adapter of the framework you don't use (`adapters/hono.ts` imports `hono`; in a Next project delete every
   `src/lib/*/adapters/hono.ts`, or `tsc` fails).
   To react to logins (welcome email, onboarding): `authRoutes({ onLogin: ({ user, isNewUser }) => … })` in Hono,
   `export const GET = callbackRouteWith({ onLogin })` in Next.js. `isNewUser` is true only the first time.
5. Login link: `<a href="/auth/login/github?returnTo=/dashboard">`. Logout: `POST /auth/logout` (a plain HTML form is redirected to `/`; `fetch` gets 204).
6. Verify: open `/auth/login/github`, finish the flow, then `GET /api/me` returns the user.

## What's inside

Paths are relative to `src/lib/auth`.

- `index.ts` — public API: `getUserFromCookieHeader`, `signOut`, `startOAuth`, `finishOAuth`, session functions, `User`.
- `adapters/hono.ts` — `sessionMiddleware`, `requireUser`, `authRoutes()`.
- `adapters/next.ts` — `loginRoute`, `callbackRoute`, `logoutRoute`, `getUser(cookies)`.
- `schema.ts` — Drizzle tables. Depends on `../db` (@core/db).

## At a glance

- **GenPM dependencies** (installed with it): [@core/db](https://genpm.net/p/@core/db)
- **npm dependencies** (proposed, never installed without asking): `arctic`, `@oslojs/crypto`, `@oslojs/encoding`
- **Environment variables** (added to `.env.example`): `AUTH_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
- **AI rules**: [`AGENTS.md`](AGENTS.md), loaded by your agent only when it works in `src/lib/auth`

## Security

GenPM installs a 40-character commit SHA (never a branch), verifies an Ed25519-signed manifest, never runs install scripts and scans AI rules for prompt injection. Details: [genpm.net/docs/security](https://genpm.net/docs/security).

## License

MIT — see [LICENSE](LICENSE). Browse the full catalog at [genpm.net](https://genpm.net).
