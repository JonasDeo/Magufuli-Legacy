import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { db } from "./db.js";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-this";
const ACCESS_EXPIRES_IN = "15m";
const REFRESH_EXPIRES_MS = 1000 * 60 * 60 * 24 * 14;
const RESET_EXPIRES_MS = 1000 * 60 * 30;

export function signAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: ACCESS_EXPIRES_IN },
  );
}

export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function issueRefreshToken(userId) {
  const raw = crypto.randomBytes(48).toString("hex");
  const now = Date.now();
  const expiresAt = now + REFRESH_EXPIRES_MS;
  db.prepare(
    "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
  ).run(userId, hashToken(raw), expiresAt, now);
  return raw;
}

export function rotateRefreshToken(rawToken) {
  const hashed = hashToken(rawToken);
  const row = db
    .prepare(
      "SELECT id, user_id AS userId, expires_at AS expiresAt, revoked_at AS revokedAt FROM refresh_tokens WHERE token_hash = ?",
    )
    .get(hashed);
  if (!row || row.revokedAt || row.expiresAt < Date.now()) return null;
  db.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?").run(Date.now(), row.id);
  return row.userId;
}

export function revokeRefreshToken(rawToken) {
  const hashed = hashToken(rawToken);
  db.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL").run(
    Date.now(),
    hashed,
  );
}

export function issuePasswordResetToken(userId) {
  const raw = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  db.prepare(
    "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
  ).run(userId, hashToken(raw), now + RESET_EXPIRES_MS, now);
  return raw;
}

export function consumePasswordResetToken(rawToken) {
  const hashed = hashToken(rawToken);
  const row = db
    .prepare(
      "SELECT id, user_id AS userId, expires_at AS expiresAt, used_at AS usedAt FROM password_reset_tokens WHERE token_hash = ?",
    )
    .get(hashed);
  if (!row || row.usedAt || row.expiresAt < Date.now()) return null;
  db.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?").run(Date.now(), row.id);
  return row.userId;
}
