import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { testDb } from '../db/__fixtures__/pglite.ts';
import { authRoutes, requireUser, sessionMiddleware } from './adapters/hono.ts';
import { callbackRoute, getUser, loginRoute } from './adapters/next.ts';
import * as schema from './schema.ts';
import {
  createSession,
  generateSessionToken,
  getUserFromCookieHeader,
  invalidateUserSessions,
  parseCookies,
  rotateSession,
  SESSION_TTL_MS,
  safeReturnTo,
  startOAuth,
  upsertOAuthUser,
  upsertOAuthUserWithStatus,
  runLoginHook,
  validateSessionToken,
} from './index.ts';

const env = { AUTH_SECRET: 'x'.repeat(40), GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-secret' };
const realFetch = globalThis.fetch;

beforeEach(async () => {
  Object.assign(process.env, env);
  await testDb(schema);
});
afterEach(() => {
  globalThis.fetch = realFetch;
  vi.useRealTimers();
});

const newUser = () => upsertOAuthUser('github', { id: String(Math.random()), email: null, emailVerified: false, name: 'A', avatarUrl: null });

describe('sessions', () => {
  it('validates, slides the expiry and expires', async () => {
    const user = await newUser();
    const token = generateSessionToken();
    expect(token).toMatch(/^[a-z2-7]{32}$/);
    const s = await createSession(token, user.id);
    expect(s.id).not.toContain(token);
    expect((await validateSessionToken(token)).user?.id).toBe(user.id);
    vi.useFakeTimers({ now: Date.now() + SESSION_TTL_MS * 0.6 });
    const renewed = await validateSessionToken(token);
    expect(renewed.session!.expiresAt.getTime()).toBeGreaterThan(s.expiresAt.getTime());
    vi.setSystemTime(Date.now() + SESSION_TTL_MS + 1000);
    expect((await validateSessionToken(token)).user).toBeNull();
    expect((await validateSessionToken('nope')).user).toBeNull();
  });

  it('rotates and invalidates', async () => {
    const user = await newUser();
    const old = generateSessionToken();
    await createSession(old, user.id);
    const r = await rotateSession(old);
    expect((await validateSessionToken(old)).user).toBeNull();
    expect((await validateSessionToken(r!.token)).user?.id).toBe(user.id);
    await invalidateUserSessions(user.id);
    expect((await validateSessionToken(r!.token)).user).toBeNull();
  });
});

describe('account linking', () => {
  it('links by verified email only', async () => {
    const a = await upsertOAuthUser('github', { id: '1', email: 'a@x.dev', emailVerified: true, name: 'A', avatarUrl: null });
    const sameGh = await upsertOAuthUser('github', { id: '1', email: 'other@x.dev', emailVerified: true, name: 'A', avatarUrl: null });
    expect(sameGh.id).toBe(a.id);
    const google = await upsertOAuthUser('google', { id: 'g1', email: 'a@x.dev', emailVerified: true, name: 'A', avatarUrl: null });
    expect(google.id).toBe(a.id);
    const attacker = await upsertOAuthUser('google', { id: 'g2', email: 'a@x.dev', emailVerified: false, name: 'E', avatarUrl: null });
    expect(attacker.id).not.toBe(a.id);
    expect(attacker.email).toBeNull();
  });
});

describe('oauth state', () => {
  it('only allows internal return paths', () => {
    expect(safeReturnTo('/dashboard?x=1')).toBe('/dashboard?x=1');
    for (const bad of ['//evil.com', 'https://evil.com', '/\\evil.com', '', null]) expect(safeReturnTo(bad)).toBe('/');
    // Los navegadores quitan tabuladores y saltos de línea: '/\t/evil.com' sería '//evil.com'.
    for (const bad of ['/\t/evil.com', '/\n/evil.com', '/\r//evil.com', '/a\\..\\evil', '/x\u0000y']) expect(safeReturnTo(bad)).toBe('/');
  });
  it('requires a strong AUTH_SECRET', () => {
    process.env.AUTH_SECRET = 'short';
    expect(() => startOAuth('github', { origin: 'http://localhost' })).toThrow(/AUTH_SECRET/);
  });
});

function fakeGitHub(user = { id: 42, login: 'octo', name: 'Octo Cat', avatar_url: 'https://a/42' }, email = 'octo@x.dev') {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url === 'https://github.com/login/oauth/access_token') {
      const body = String(init?.body ?? (input instanceof Request ? await input.text() : ''));
      if (!body.includes('code=good')) return Response.json({ error: 'bad_verification_code' }, { status: 400 });
      return Response.json({ access_token: 'gho_x', token_type: 'bearer', scope: 'read:user,user:email' });
    }
    if (url === 'https://api.github.com/user') return Response.json(user);
    if (url === 'https://api.github.com/user/emails') return Response.json([{ email, primary: true, verified: true }]);
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
}

describe('Hono adapter', () => {
  const app = () =>
    new Hono()
      .use(sessionMiddleware)
      .route('/auth', authRoutes())
      .get('/me', requireUser, (c) => c.json({ id: (c.get('user') as { id: string }).id }));

  it('logs in with GitHub, protects routes and logs out', async () => {
    fakeGitHub();
    const a = app();
    expect((await a.request('/me')).status).toBe(401);
    const login = await a.request('/auth/login/github?returnTo=/dashboard');
    expect(login.status).toBe(302);
    const to = new URL(login.headers.get('location')!);
    expect(to.origin).toBe('https://github.com');
    expect(to.searchParams.get('redirect_uri')).toBe('http://localhost/auth/callback/github');
    const stateCookie = login.headers.get('set-cookie')!.split(';')[0]!;

    const tampered = await a.request(`/auth/callback/github?code=good&state=${to.searchParams.get('state')}`, {
      headers: { cookie: `${stateCookie.slice(0, -3)}abc` },
    });
    expect(tampered.status).toBe(400);
    const wrongState = await a.request('/auth/callback/github?code=good&state=other', { headers: { cookie: stateCookie } });
    expect(wrongState.status).toBe(400);
    const badCode = await a.request(`/auth/callback/github?code=bad&state=${to.searchParams.get('state')}`, {
      headers: { cookie: stateCookie },
    });
    expect(badCode.status).toBe(502);

    const cb = await a.request(`/auth/callback/github?code=good&state=${to.searchParams.get('state')}`, {
      headers: { cookie: stateCookie },
    });
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')).toBe('/dashboard');
    const session = cb.headers.getSetCookie().find((c) => c.startsWith('session='))!;
    expect(session).toMatch(/HttpOnly; SameSite=Lax/);
    const cookie = session.split(';')[0]!;
    const me = await a.request('/me', { headers: { cookie } });
    expect(me.status).toBe(200);
    const user = await getUserFromCookieHeader(cookie);
    expect(user).toMatchObject({ name: 'Octo Cat', email: 'octo@x.dev' });

    const out = await a.request('/auth/logout', { method: 'POST', headers: { cookie } });
    expect(out.headers.get('set-cookie')).toMatch(/Max-Age=0/);
    expect((await a.request('/me', { headers: { cookie } })).status).toBe(401);
  });

  it('404s on providers that are not configured', async () => {
    expect((await app().request('/auth/login/google')).status).toBe(404);
  });
});

describe('Next adapter', () => {
  it('runs the same flow with standard Request/Response', async () => {
    fakeGitHub({ id: 7, login: 'nx', name: 'Next User', avatar_url: 'https://a/7' }, 'nx@x.dev');
    const params = Promise.resolve({ provider: 'github' });
    const login = await loginRoute(new Request('https://app.test/auth/login/github'), { params });
    const state = new URL(login.headers.get('location')!).searchParams.get('state');
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
    const cb = await callbackRoute(new Request(`https://app.test/auth/callback/github?code=good&state=${state}`, { headers: { cookie } }), {
      params: Promise.resolve({ provider: 'github' }),
    });
    expect(cb.status).toBe(302);
    const token = parseCookies(cb.headers.getSetCookie().find((c) => c.startsWith('session='))!.split(';')[0])['session']!;
    const user = await getUser({ get: (n) => (n === 'session' ? { value: token } : undefined) });
    expect(user?.email).toBe('nx@x.dev');
    expect(await getUser({ get: () => undefined })).toBeNull();
  });
});

describe('usuario nuevo y onLogin', () => {
  it('created solo la primera vez', async () => {
    const p = { id: 'n1', email: 'n@x.dev', emailVerified: true, name: 'N', avatarUrl: null };
    expect((await upsertOAuthUserWithStatus('github', p)).created).toBe(true);
    expect((await upsertOAuthUserWithStatus('github', p)).created).toBe(false);
    // Enlazar otro proveedor al mismo email verificado no es un usuario nuevo.
    expect((await upsertOAuthUserWithStatus('google', { ...p, id: 'g9' })).created).toBe(false);
  });
  it('un error en onLogin no rompe el login', async () => {
    const user = await newUser();
    await expect(runLoginHook(() => { throw new Error('boom'); }, { user, isNewUser: true, provider: 'github' })).resolves.toBeUndefined();
  });
});
