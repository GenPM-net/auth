// Cookies de sesión y de estado OAuth, sin dependencias de framework (devuelven cabeceras Set-Cookie).
import { SESSION_TTL_MS } from './session.js';

export const SESSION_COOKIE = 'session';

const secure = () => process.env.NODE_ENV === 'production';

export function serializeCookie(name: string, value: string, maxAgeSeconds: number): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`];
  if (secure()) parts.push('Secure');
  return parts.join('; ');
}

export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    try {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    } catch {
      // cookie mal codificada: se ignora
    }
  }
  return out;
}

export const sessionCookie = (token: string) => serializeCookie(SESSION_COOKIE, token, SESSION_TTL_MS / 1000);
export const clearSessionCookie = () => serializeCookie(SESSION_COOKIE, '', 0);
