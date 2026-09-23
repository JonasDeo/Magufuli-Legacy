import pg from "pg";
import bcrypt from "bcryptjs";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:postgres@localhost:5432/magufuli",
});

export async function query(text, params) {
  return pool.query(text, params);
}

export async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      is_banned BOOLEAN NOT NULL DEFAULT FALSE,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threads (
      id SERIAL PRIMARY KEY,
      tag TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      is_pinned BOOLEAN NOT NULL DEFAULT FALSE,
      is_locked BOOLEAN NOT NULL DEFAULT FALSE,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS replies (
      id SERIAL PRIMARY KEY,
      thread_id INTEGER NOT NULL REFERENCES threads(id),
      body TEXT NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS feedback (
      id SERIAL PRIMARY KEY,
      section_id TEXT NOT NULL,
      vote TEXT,
      comment TEXT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL,
      UNIQUE(section_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      token_hash TEXT NOT NULL UNIQUE,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      revoked_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      token_hash TEXT NOT NULL UNIQUE,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      used_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      actor_id INTEGER NOT NULL REFERENCES users(id),
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id INTEGER NOT NULL,
      details JSONB NOT NULL DEFAULT '{}',
      created_at BIGINT NOT NULL
    );
  `);

  const { rows: threadRows } = await query("SELECT COUNT(*)::int AS count FROM threads");
  if (threadRows[0].count === 0) {
    const now = Date.now();
    const seedHash = "$2b$10$Wn9WXmglQj7E8i7x6NOv8eEewhMecvErDO8xYf5s6SM6jwN8jMbu2";
    const { rows: seedUsers } = await query(
      `INSERT INTO users (name, email, password_hash, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
       RETURNING id`,
      ["Seed User", "seed@magufuli.local", seedHash, now],
    );
    const userId = seedUsers[0].id;

    await query(
      `INSERT INTO threads (tag, title, body, user_id, created_at, updated_at) VALUES
       ($1, $2, $3, $4, $5, $6),
       ($7, $8, $9, $4, $10, $11)`,
      [
        "Verdict",
        "Hero or villain? Your verdict on Magufuli's presidency",
        "I'll start: the infrastructure is undeniable, but the press crackdown crossed a line for me. Where do you land?",
        userId,
        now - 2 * 60 * 60 * 1000,
        now - 2 * 60 * 60 * 1000,
        "Health",
        "Did he really die of a heart attack? The COVID speculation",
        "Official cause was heart complications. Hospitals reported different patterns. Cite sources if you can.",
        now - 48 * 60 * 60 * 1000,
        now - 48 * 60 * 60 * 1000,
      ],
    );
  }

  const adminEmail = "admin@magufuli.local";
  const { rows: adminRows } = await query("SELECT id FROM users WHERE email = $1", [adminEmail]);
  if (adminRows.length === 0) {
    const hash = await bcrypt.hash("Admin123!", 10);
    await query(
      "INSERT INTO users (name, email, password_hash, role, created_at) VALUES ($1, $2, $3, $4, $5)",
      ["Admin", adminEmail, hash, "admin", Date.now()],
    );
  }
}
