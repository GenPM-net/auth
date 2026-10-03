// OAuth con GitHub y Google (arctic). Núcleo sin framework: los adaptadores pasan el origen, la URL de callback y la
// cabecera Cookie, y devuelven las cabeceras Set-Cookie que les damos.
import { hmac } from '@oslojs/crypto/hmac';
import { SHA256 } from '@oslojs/crypto/sha2';
import { decodeBase64urlIgnorePadding, encodeBase64urlNoPadding } from '@oslojs/encoding';
import { decodeIdToken, GitHub, Google, generateCodeVerifier, generateState } from 'arctic';
import { and, eq } from 'drizzle-orm';
import { type Executor, getDb, withTransaction } from '../db/index.js';
import { parseCookies, serializeCookie, sessionCookie } from './cookies.js';
import { oauthAccounts, type User, users } from './schema.js';
import { createSession, generateSessionToken } from './session.js';

export type Provider = 'github' | 'google';
export type AuthErrorCode = 'provider_disabled' | 'invalid_state' | 'oauth_failed' | 'missing_secret';

export class AuthError extends Error {
  constructor(
    readonly code: AuthErrorCode,
    message: string,
  ) {
    super(message);
  }
}

const STATE_COOKIE = 'oauth_state';
const STATE_TTL_S = 600;

export function enabledProviders(env: NodeJS.ProcessEnv = process.env): Provider[] {
  const out: Provider[] = [];
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) out.push('github');
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) out.push('google');
  return out;
}

export const callbackPath = (provider: Provider) => `/auth/callback/${provider}`;

function client(provider: Provider, origin: string) {
  const env = process.env;
  if (!enabledProviders().includes(provider)) throw new AuthError('provider_disabled', `${provider} is not configured`);
  const redirect = new URL(callbackPath(provider), origin).toString();
  return provider === 'github'
    ? new GitHub(env.GITHUB_CLIENT_ID!, env.GITHUB_CLIENT_SECRET!, redirect)
    : new Google(env.GOOGLE_CLIENT_ID!, env.GOOGLE_CLIENT_SECRET!, redirect);
}

function secret(): Uint8Array {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) throw new AuthError('missing_secret', 'AUTH_SECRET must be at least 32 characters');
  return new TextEncoder().encode(s);
}

type State = { s: string; v?: string; r: string; p: Provider };

function sign(data: State): string {
  const body = encodeBase64urlNoPadding(new TextEncoder().encode(JSON.stringify(data)));
  const mac = encodeBase64urlNoPadding(hmac(SHA256, secret(), new TextEncoder().encode(body)));
  return `${body}.${mac}`;
}

function verify(value: string | undefined): State | null {
  if (!value) return null;
  const [body, mac] = value.split('.');
  if (!body || !mac) return null;
  const expected = encodeBase64urlNoPadding(hmac(SHA256, secret(), new TextEncoder().encode(body)));
  if (expected.length !== mac.length) return null;
  let diff = 0;
  for (let i = 0; i < mac.length; i++) diff |= expected.charCodeAt(i) ^ mac.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    return JSON.parse(new TextDecoder().decode(decodeBase64urlIgnorePadding(body))) as State;
  } catch {
    return null;
  }
}

/** Solo rutas internas: evita redirecciones abiertas (`//evil.com`, `https://…`). */
export function safeReturnTo(value: string | null | undefined): string {
  return value && value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/\\') ? value : '/';
}

export function startOAuth(
  provider: Provider,
  opts: { origin: string; returnTo?: string | null },
): { url: URL; setCookie: string } {
  const c = client(provider, opts.origin);
  const state = generateState();
  const r = safeReturnTo(opts.returnTo);
  if (c instanceof GitHub) {
    return {
      url: c.createAuthorizationURL(state, ['read:user', 'user:email']),
      setCookie: serializeCookie(STATE_COOKIE, sign({ s: state, r, p: provider }), STATE_TTL_S),
    };
  }
  const verifier = generateCodeVerifier();
  return {
    url: c.createAuthorizationURL(state, verifier, ['openid', 'profile', 'email']),
    setCookie: serializeCookie(STATE_COOKIE, sign({ s: state, v: verifier, r, p: provider }), STATE_TTL_S),
  };
}

export type Profile = { id: string; email: string | null; emailVerified: boolean; name: string | null; avatarUrl: string | null };

async function githubProfile(accessToken: string): Promise<Profile> {
  const get = async <T>(path: string): Promise<T> => {
    const res = await fetch(`https://api.github.com${path}`, {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'core-auth' },
    });
    if (!res.ok) throw new AuthError('oauth_failed', `GitHub ${path} ${res.status}`);
    return (await res.json()) as T;
  };
  const u = await get<{ id: number; login: string; name: string | null; avatar_url: string | null }>('/user');
  const emails = await get<Array<{ email: string; primary: boolean; verified: boolean }>>('/user/emails');
  const primary = emails.find((e) => e.primary && e.verified) ?? null;
  return {
    id: String(u.id),
    email: primary?.email ?? null,
    emailVerified: !!primary,
    name: u.name ?? u.login,
    avatarUrl: u.avatar_url,
  };
}

function googleProfile(idToken: string): Profile {
  const c = decodeIdToken(idToken) as { sub: string; email?: string; email_verified?: boolean; name?: string; picture?: string };
  return {
    id: c.sub,
    email: c.email ?? null,
    emailVerified: c.email_verified === true,
    name: c.name ?? null,
    avatarUrl: c.picture ?? null,
  };
}

/**
 * Busca la cuenta OAuth; si no existe, enlaza con el usuario del mismo email **verificado** o crea uno nuevo.
 * Nunca enlaza por un email sin verificar (toma de cuentas).
 */
export async function upsertOAuthUser(provider: Provider, p: Profile, db: Executor = getDb()): Promise<User> {
  const run = async (tx: Executor) => {
    const [linked] = await tx
      .select({ user: users })
      .from(oauthAccounts)
      .innerJoin(users, eq(oauthAccounts.userId, users.id))
      .where(and(eq(oauthAccounts.provider, provider), eq(oauthAccounts.providerUserId, p.id)));
    if (linked) return linked.user;
    let user: User | undefined;
    if (p.email && p.emailVerified) [user] = await tx.select().from(users).where(eq(users.email, p.email));
    if (!user) {
      [user] = await tx
        .insert(users)
        .values({ email: p.emailVerified ? p.email : null, name: p.name, avatarUrl: p.avatarUrl })
        .returning();
    }
    await tx.insert(oauthAccounts).values({ provider, providerUserId: p.id, userId: user!.id });
    return user!;
  };
  return db === getDb() ? withTransaction(run) : run(db);
}

/** Completa el login: valida el estado, canjea el código, crea/enlaza el usuario y abre una sesión. */
export async function finishOAuth(
  provider: Provider,
  opts: { url: string | URL; cookieHeader: string | null | undefined },
): Promise<{ user: User; token: string; setCookies: string[]; returnTo: string }> {
  const url = new URL(opts.url);
  const state = verify(parseCookies(opts.cookieHeader)[STATE_COOKIE]);
  const code = url.searchParams.get('code');
  if (!state || state.p !== provider || !code || url.searchParams.get('state') !== state.s) {
    throw new AuthError('invalid_state', 'OAuth state mismatch: start the login again');
  }
  const c = client(provider, url.origin);
  let profile: Profile;
  try {
    profile =
      c instanceof GitHub
        ? await githubProfile((await c.validateAuthorizationCode(code)).accessToken())
        : googleProfile((await c.validateAuthorizationCode(code, state.v ?? '')).idToken());
  } catch (e) {
    if (e instanceof AuthError) throw e;
    throw new AuthError('oauth_failed', `${provider} rejected the authorization code`);
  }
  const user = await upsertOAuthUser(provider, profile);
  const token = generateSessionToken();
  await createSession(token, user.id);
  return { user, token, setCookies: [sessionCookie(token), serializeCookie(STATE_COOKIE, '', 0)], returnTo: state.r };
}
