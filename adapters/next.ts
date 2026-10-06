// Adaptador Next.js (App Router). Sin importar `next`: usa Request/Response estándar.
//   app/auth/login/[provider]/route.ts     → export const GET = loginRoute;
//   app/auth/callback/[provider]/route.ts  → export const GET = callbackRoute;  (o callbackRouteWith({ onLogin }))
//   app/auth/logout/route.ts               → export const POST = logoutRoute;
//   Server Components: `const user = await getUser(await cookies())` (cookies de 'next/headers').
import { AuthError, enabledProviders, finishOAuth, getUserFromCookieHeader, type LoginHook, type Provider, runLoginHook, SESSION_COOKIE, signOut, startOAuth, type User } from '../index.ts';

type Ctx = { params: Promise<{ provider: string }> };
type CookieStore = { get(name: string): { value: string } | undefined };

const isProvider = (p: string): p is Provider => (enabledProviders() as string[]).includes(p);
const json = (body: unknown, status: number) => Response.json(body, { status });

export async function loginRoute(req: Request, ctx: Ctx): Promise<Response> {
  const { provider } = await ctx.params;
  if (!isProvider(provider)) return json({ error: 'unknown_provider' }, 404);
  const url = new URL(req.url);
  const { url: to, setCookie } = startOAuth(provider, { origin: url.origin, returnTo: url.searchParams.get('returnTo') });
  return new Response(null, { status: 302, headers: { location: to.toString(), 'set-cookie': setCookie } });
}

/** Callback con `onLogin` (se llama tras cada login correcto con `isNewUser`). */
export function callbackRouteWith(opts: { onLogin?: LoginHook } = {}) {
  return (req: Request, ctx: Ctx) => callback(req, ctx, opts.onLogin);
}

export function callbackRoute(req: Request, ctx: Ctx): Promise<Response> {
  return callback(req, ctx);
}

async function callback(req: Request, ctx: Ctx, onLogin?: LoginHook): Promise<Response> {
  const { provider } = await ctx.params;
  if (!isProvider(provider)) return json({ error: 'unknown_provider' }, 404);
  try {
    const r = await finishOAuth(provider, { url: req.url, cookieHeader: req.headers.get('cookie') });
    await runLoginHook(onLogin, { user: r.user, isNewUser: r.isNewUser, provider });
    const headers = new Headers({ location: r.returnTo });
    for (const c of r.setCookies) headers.append('set-cookie', c);
    return new Response(null, { status: 302, headers });
  } catch (e) {
    if (e instanceof AuthError) return json({ error: e.code }, e.code === 'invalid_state' ? 400 : 502);
    throw e;
  }
}

export async function logoutRoute(req: Request): Promise<Response> {
  return new Response(null, { status: 204, headers: { 'set-cookie': await signOut(req.headers.get('cookie')) } });
}

/** Usuario actual en Server Components / Route Handlers: `getUser(await cookies())`. */
export async function getUser(cookies: CookieStore): Promise<User | null> {
  const token = cookies.get(SESSION_COOKIE)?.value;
  return token ? getUserFromCookieHeader(`${SESSION_COOKIE}=${encodeURIComponent(token)}`) : null;
}
