import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import fs from "node:fs";
import path from "node:path";

const dataDir = path.resolve(process.cwd(), "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, "app.db");
export const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  is_banned INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS threads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  is_pinned INTEGER NOT NULL DEFAULT 0,
  is_locked INTEGER NOT NULL DEFAULT 0,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS replies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(thread_id) REFERENCES threads(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  section_id TEXT NOT NULL,
  vote TEXT,
  comment TEXT,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(section_id, user_id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function addColumnIfMissing(table, columnDef) {
  const colName = columnDef.split(" ")[0];
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = cols.some((c) => c.name === colName);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`);
  }
}

addColumnIfMissing("users", "role TEXT NOT NULL DEFAULT 'user'");
addColumnIfMissing("users", "is_banned INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("threads", "is_pinned INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("threads", "is_locked INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("threads", "is_deleted INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("replies", "is_deleted INTEGER NOT NULL DEFAULT 0");

const threadCount = db.prepare("SELECT COUNT(*) AS count FROM threads").get().count;
if (threadCount === 0) {
  const now = Date.now();
  const seedUser = db
    .prepare("INSERT OR IGNORE INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)")
    .run("Seed User", "seed@magufuli.local", "$2b$10$Wn9WXmglQj7E8i7x6NOv8eEewhMecvErDO8xYf5s6SM6jwN8jMbu2", now);
  const userId =
    seedUser.lastInsertRowid ||
    db.prepare("SELECT id FROM users WHERE email = ?").get("seed@magufuli.local").id;

  const insertThread = db.prepare(
    "INSERT INTO threads (tag, title, body, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
  );

  insertThread.run(
    "Verdict",
    "Hero or villain? Your verdict on Magufuli's presidency",
    "I'll start: the infrastructure is undeniable, but the press crackdown crossed a line for me. Where do you land?",
    userId,
    now - 2 * 60 * 60 * 1000,
    now - 2 * 60 * 60 * 1000,
  );
  insertThread.run(
    "Health",
    "Did he really die of a heart attack? The COVID speculation",
    "Official cause was heart complications. Hospitals reported different patterns. Cite sources if you can.",
    userId,
    now - 48 * 60 * 60 * 1000,
    now - 48 * 60 * 60 * 1000,
  );
}

const adminEmail = "admin@magufuli.local";
const adminExists = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
if (!adminExists) {
  db.prepare(
    "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
  ).run("Admin", adminEmail, bcrypt.hashSync("Admin123!", 10), "admin", Date.now());
}
