CREATE TABLE users (id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER NOT NULL);
--> statement-breakpoint
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
--> statement-breakpoint
CREATE TABLE states (user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0);
--> statement-breakpoint
CREATE TABLE rate_limits (key TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL, expires_at INTEGER NOT NULL);
