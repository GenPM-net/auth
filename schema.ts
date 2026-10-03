// Tablas de @core/auth. Las recoge drizzle-kit vía src/lib/db/drizzle.config.ts.
import { index, pgTable, primaryKey, text, timestamp } from 'drizzle-orm/pg-core';
import { primaryId, timestamps } from '../db/index.js';

export const users = pgTable('users', {
  id: primaryId('usr'),
  email: text('email').unique(),
  name: text('name'),
  avatarUrl: text('avatar_url'),
  ...timestamps,
});

/** El id de la sesión es el SHA-256 del token: un volcado de la BD no permite suplantar a nadie. */
export const authSessions = pgTable(
  'auth_sessions',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
    ...timestamps,
  },
  (t) => [index('auth_sessions_user_idx').on(t.userId)],
);

export const oauthAccounts = pgTable(
  'oauth_accounts',
  {
    provider: text('provider', { enum: ['github', 'google'] }).notNull(),
    providerUserId: text('provider_user_id').notNull(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    ...timestamps,
  },
  (t) => [primaryKey({ columns: [t.provider, t.providerUserId] }), index('oauth_accounts_user_idx').on(t.userId)],
);

export type User = typeof users.$inferSelect;
export type Session = typeof authSessions.$inferSelect;
