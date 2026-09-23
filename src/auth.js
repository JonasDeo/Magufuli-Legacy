import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { query } from "./db.js";

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

export async function issueRefreshToken(userId) {
  const raw = crypto.randomBytes(48).toString("hex");
  const now = Date.now();
  const expiresAt = now + REFRESH_EXPIRES_MS;
  await query(
    "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4)",
    [userId, hashToken(raw), expiresAt, now],
  );
  return raw;
}

export async function rotateRefreshToken(rawToken) {
  const hashed = hashToken(rawToken);
  const { rows } = await query(
    `SELECT id, user_id AS "userId", expires_at AS "expiresAt", revoked_at AS "revokedAt"
     FROM refresh_tokens WHERE token_hash = $1`,
    [hashed],
  );
  const row = rows[0];
  if (!row || row.revokedAt || row.expiresAt < Date.now()) return null;
  await query("UPDATE refresh_tokens SET revoked_at = $1 WHERE id = $2", [Date.now(), row.id]);
  return row.userId;
}

export async function revokeRefreshToken(rawToken) {
  const hashed = hashToken(rawToken);
  await query(
    "UPDATE refresh_tokens SET revoked_at = $1 WHERE token_hash = $2 AND revoked_at IS NULL",
    [Date.now(), hashed],
  );
}

export async function issuePasswordResetToken(userId) {
  const raw = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  await query(
    "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4)",
    [userId, hashToken(raw), now + RESET_EXPIRES_MS, now],
  );
  return raw;
}

export async function consumePasswordResetToken(rawToken) {
  const hashed = hashToken(rawToken);
  const { rows } = await query(
    `SELECT id, user_id AS "userId", expires_at AS "expiresAt", used_at AS "usedAt"
     FROM password_reset_tokens WHERE token_hash = $1`,
    [hashed],
  );
  const row = rows[0];
  if (!row || row.usedAt || row.expiresAt < Date.now()) return null;
  await query("UPDATE password_reset_tokens SET used_at = $1 WHERE id = $2", [Date.now(), row.id]);
  return row.userId;
}
