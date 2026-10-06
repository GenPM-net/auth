# @core/auth — rules for AI agents

## Purpose
Cookie sessions (random token, only its SHA-256 stored, 30-day sliding expiry, rotation) and OAuth login with GitHub
and Google via `arctic`. Tables: `users`, `auth_sessions`, `oauth_accounts`. No roles or permissions (out of scope:
build them in your app on top of `users.id`). No passwords.

## Map
- `index.ts` — public API: `getUserFromCookieHeader`, `signOut`, `startOAuth`, `finishOAuth`, session functions, `User`.
- `adapters/hono.ts` — `sessionMiddleware`, `requireUser`, `authRoutes()`.
- `adapters/next.ts` — `loginRoute`, `callbackRoute`, `logoutRoute`, `getUser(cookies)`.
- `schema.ts` — Drizzle tables. Depends on `../db` (@core/db).

## Integration
1. Env: `AUTH_SECRET` (≥ 32 random chars, e.g. `openssl rand -base64 32`), `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.
   Optional Google: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`. Providers without both vars are disabled.
2. OAuth app callback URL: `<origin>/auth/callback/github` (and `/auth/callback/google`).
3. Generate and apply migrations (see `src/lib/db/AGENTS.md`).
4. Hono:
   ```ts
   import { authRoutes, requireUser, sessionMiddleware } from './lib/auth/adapters/hono.js';
   app.use(sessionMiddleware);
   app.route('/auth', authRoutes());
   app.get('/api/me', requireUser, (c) => c.json(c.get('user')));
   ```
   Next.js (App Router): create `app/auth/login/[provider]/route.ts` with `export { loginRoute as GET } from '@/lib/auth/adapters/next'`,
   the same for `callback/[provider]` (`callbackRoute`) and `app/auth/logout/route.ts` (`logoutRoute as POST`).
   In Server Components: `const user = await getUser(await cookies())`.
   Delete the adapter of the framework you don't use (`adapters/hono.ts` imports `hono`).
   To react to logins (welcome email, onboarding): `authRoutes({ onLogin: ({ user, isNewUser }) => … })` in Hono,
   `export const GET = callbackRouteWith({ onLogin })` in Next.js. `isNewUser` is true only the first time.
5. Login link: `<a href="/auth/login/github?returnTo=/dashboard">`. Logout: `POST /auth/logout`.
6. Verify: open `/auth/login/github`, finish the flow, then `GET /api/me` returns the user.

## Conventions
- Read the current user only through `sessionMiddleware`/`getUser`; never parse the cookie yourself.
- Other modules reference `users.id` (text, `usr_…`) with `onDelete: 'cascade'` or `set null`.
- Call `rotateSession` after a privilege change and `invalidateUserSessions` when an account is compromised.
- If you installed `@core/db` with `--dest`, fix the `../db/index.js` imports here.

## Don't
- Don't store or log session tokens, OAuth codes or `AUTH_SECRET`.
- Don't link accounts by unverified email; `upsertOAuthUser` already enforces it.
- Don't accept absolute `returnTo` URLs (open redirect); use `safeReturnTo`.
- Don't make GET requests log users out, and don't disable `HttpOnly`/`SameSite` on the cookie.
