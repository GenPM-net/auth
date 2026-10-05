// Adaptador Hono: `app.route('/auth', authRoutes())`, `app.use(sessionMiddleware)` y `requireUser` en rutas privadas.
import type { MiddlewareHandler } from 'hono';
import { Hono } from 'hono';
import { AuthError, enabledProviders, finishOAuth, getUserFromCookieHeader, type LoginHook, type Provider, runLoginHook, signOut, startOAuth, type User } from '../index.js';

export type AuthVariables = { user: User | null };

/** Carga `c.get('user')` (o null) en cada petición. */
export const sessionMiddleware: MiddlewareHandler<{ Variables: AuthVariables }> = async (c, next) => {
  c.set('user', await getUserFromCookieHeader(c.req.header('cookie')));
  await next();
};

/** 401 si no hay usuario. Úsalo después de `sessionMiddleware`. */
export const requireUser: MiddlewareHandler<{ Variables: AuthVariables }> = async (c, next) => {
  if (!c.get('user')) return c.json({ error: 'unauthorized' }, 401);
  await next();
};

const isProvider = (p: string): p is Provider => (enabledProviders() as string[]).includes(p);

/**
 * GET /login/:provider?returnTo=/x · GET /callback/:provider · POST /logout. Monta en '/auth'.
 * `onLogin` se llama tras cada login correcto con `isNewUser` (p. ej. para el correo de bienvenida).
 */
export function authRoutes(opts: { onLogin?: LoginHook } = {}) {
  return new Hono()
    .get('/login/:provider', (c) => {
      const provider = c.req.param('provider');
      if (!isProvider(provider)) return c.json({ error: 'unknown_provider' }, 404);
      const { url, setCookie } = startOAuth(provider, { origin: new URL(c.req.url).origin, returnTo: c.req.query('returnTo') });
      c.header('set-cookie', setCookie);
      return c.redirect(url.toString(), 302);
    })
    .get('/callback/:provider', async (c) => {
      const provider = c.req.param('provider');
      if (!isProvider(provider)) return c.json({ error: 'unknown_provider' }, 404);
      try {
        const r = await finishOAuth(provider, { url: c.req.url, cookieHeader: c.req.header('cookie') });
        await runLoginHook(opts.onLogin, { user: r.user, isNewUser: r.isNewUser, provider });
        for (const cookie of r.setCookies) c.header('set-cookie', cookie, { append: true });
        return c.redirect(r.returnTo, 302);
      } catch (e) {
        if (e instanceof AuthError) return c.json({ error: e.code }, e.code === 'invalid_state' ? 400 : 502);
        throw e;
      }
    })
    .post('/logout', async (c) => {
      c.header('set-cookie', await signOut(c.req.header('cookie')));
      return c.body(null, 204);
    });
}
