// @core/auth — API pública. Importa desde aquí; las rutas web están en adapters/hono.ts y adapters/next.ts.
import { clearSessionCookie, parseCookies, SESSION_COOKIE } from './cookies.ts';
import type { User } from './schema.ts';
import { invalidateSession, validateSessionToken } from './session.ts';

export { clearSessionCookie, parseCookies, SESSION_COOKIE, sessionCookie } from './cookies.ts';
export {
  AuthError,
  type AuthErrorCode,
  callbackPath,
  enabledProviders,
  finishOAuth,
  type LoginHook,
  type Profile,
  type Provider,
  safeReturnTo,
  startOAuth,
  runLoginHook,
  upsertOAuthUser,
  upsertOAuthUserWithStatus,
} from './oauth.ts';
export { authSessions, oauthAccounts, type Session, type User, users } from './schema.ts';
export {
  createSession,
  generateSessionToken,
  invalidateSession,
  invalidateUserSessions,
  rotateSession,
  SESSION_TTL_MS,
  type SessionValidation,
  validateSessionToken,
} from './session.ts';

/** Usuario de una petición a partir de su cabecera Cookie (null si no hay sesión válida). */
export async function getUserFromCookieHeader(cookieHeader: string | null | undefined): Promise<User | null> {
  const token = parseCookies(cookieHeader)[SESSION_COOKIE];
  return token ? (await validateSessionToken(token)).user : null;
}

/** Cierra la sesión de la petición y devuelve la cabecera Set-Cookie que borra la cookie. */
export async function signOut(cookieHeader: string | null | undefined): Promise<string> {
  const token = parseCookies(cookieHeader)[SESSION_COOKIE];
  if (token) await invalidateSession(token);
  return clearSessionCookie();
}
