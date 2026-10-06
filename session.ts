// Sesiones con token opaco en cookie (https://lucia-auth.com/sessions/basic): 160 bits aleatorios; en BD solo su
// SHA-256. Expiración deslizante: 30 días, renovada cuando queda menos de la mitad.
import { sha256 } from '@oslojs/crypto/sha2';
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from '@oslojs/encoding';
import { eq } from 'drizzle-orm';
import { type Executor, getDb } from '../db/index.js';
import { authSessions, type Session, type User, users } from './schema.js';

const DAY = 86_400_000;
export const SESSION_TTL_MS = 30 * DAY;

export function generateSessionToken(): string {
  return encodeBase32LowerCaseNoPadding(crypto.getRandomValues(new Uint8Array(20)));
}

const sessionId = (token: string) => encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

export async function createSession(token: string, userId: string, db: Executor = getDb()): Promise<Session> {
  const [session] = await db
    .insert(authSessions)
    .values({ id: sessionId(token), userId, expiresAt: new Date(Date.now() + SESSION_TTL_MS) })
    .returning();
  return session!;
}

export type SessionValidation = { session: Session; user: User } | { session: null; user: null };

/** Valida el token de la cookie. Borra la sesión si caducó y extiende la expiración si toca. */
export async function validateSessionToken(token: string, db: Executor = getDb()): Promise<SessionValidation> {
  const id = sessionId(token);
  const [row] = await db
    .select({ session: authSessions, user: users })
    .from(authSessions)
    .innerJoin(users, eq(authSessions.userId, users.id))
    .where(eq(authSessions.id, id));
  if (!row) return { session: null, user: null };
  const { session, user } = row;
  const now = Date.now();
  if (now >= session.expiresAt.getTime()) {
    await db.delete(authSessions).where(eq(authSessions.id, id));
    return { session: null, user: null };
  }
  if (now >= session.expiresAt.getTime() - SESSION_TTL_MS / 2) {
    session.expiresAt = new Date(now + SESSION_TTL_MS);
    await db.update(authSessions).set({ expiresAt: session.expiresAt }).where(eq(authSessions.id, id));
  }
  return { session, user };
}

export async function invalidateSession(token: string, db: Executor = getDb()): Promise<void> {
  await db.delete(authSessions).where(eq(authSessions.id, sessionId(token)));
}

/** Cierra todas las sesiones de un usuario (cambio de credenciales, "cerrar sesión en todos los dispositivos"). */
export async function invalidateUserSessions(userId: string, db: Executor = getDb()): Promise<void> {
  await db.delete(authSessions).where(eq(authSessions.userId, userId));
}

/** Rotación: nuevo token para el mismo usuario y el viejo deja de valer (tras login o cambio de privilegios). */
export async function rotateSession(oldToken: string, db: Executor = getDb()): Promise<{ token: string } | null> {
  const { user } = await validateSessionToken(oldToken, db);
  if (!user) return null;
  const token = generateSessionToken();
  await createSession(token, user.id, db);
  await invalidateSession(oldToken, db);
  return { token };
}
