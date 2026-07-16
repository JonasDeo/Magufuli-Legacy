import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { db } from "./db.js";
import {
  consumePasswordResetToken,
  issuePasswordResetToken,
  issueRefreshToken,
  revokeRefreshToken,
  rotateRefreshToken,
  signAccessToken,
} from "./auth.js";
import { requireAuth, requireRole } from "./middleware.js";

const app = express();
const PORT = Number(process.env.PORT || 4000);
const ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";

app.use(cors({ origin: ORIGIN, credentials: true }));
app.use(express.json());
app.use(morgan("dev"));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many auth requests. Please try again later." },
});

const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Slow down." },
});

const registerSchema = z.object({
  name: z.string().min(2).max(120),
  email: z.string().email(),
  password: z.string().min(6).max(128),
});
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});
const refreshSchema = z.object({ refreshToken: z.string().min(20) });
const forgotSchema = z.object({ email: z.string().email() });
const resetSchema = z.object({ token: z.string().min(20), password: z.string().min(6).max(128) });
const threadSchema = z.object({
  tag: z.string().min(2).max(40),
  title: z.string().min(5).max(200),
  body: z.string().min(3).max(5000),
});
const replySchema = z.object({ body: z.string().min(1).max(3000) });
const feedbackSchema = z.object({
  sectionId: z.string().min(1).max(120),
  vote: z.enum(["up", "down"]).nullable().optional(),
  comment: z.string().max(1000).optional(),
});

function parse(schema, req, res) {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid request" });
    return null;
  }
  return parsed.data;
}

function issueAuthResponse(user) {
  const accessToken = signAccessToken(user);
  const refreshToken = issueRefreshToken(user.id);
  return { user, accessToken, refreshToken };
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const data = parse(registerSchema, req, res);
  if (!data) return;
  const { name, email, password } = data;

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const now = Date.now();
  const result = db
    .prepare("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, 'user', ?)")
    .run(name, email.toLowerCase(), passwordHash, now);
  const user = db
    .prepare("SELECT id, name, email, role, created_at AS createdAt FROM users WHERE id = ?")
    .get(result.lastInsertRowid);
  return res.status(201).json(issueAuthResponse(user));
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const data = parse(loginSchema, req, res);
  if (!data) return;
  const { email, password } = data;

  const row = db
    .prepare(
      "SELECT id, name, email, role, is_banned AS isBanned, password_hash, created_at AS createdAt FROM users WHERE email = ?",
    )
    .get(email.toLowerCase());
  if (!row) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  if (row.isBanned) return res.status(403).json({ error: "Account is banned" });

  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const user = {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    createdAt: row.createdAt,
  };
  return res.json(issueAuthResponse(user));
});

app.post("/api/auth/refresh", authLimiter, (req, res) => {
  const data = parse(refreshSchema, req, res);
  if (!data) return;
  const userId = rotateRefreshToken(data.refreshToken);
  if (!userId) return res.status(401).json({ error: "Invalid refresh token" });
  const user = db
    .prepare("SELECT id, name, email, role, created_at AS createdAt FROM users WHERE id = ?")
    .get(userId);
  if (!user) return res.status(401).json({ error: "Invalid refresh token" });
  return res.json(issueAuthResponse(user));
});

app.post("/api/auth/logout", (req, res) => {
  const data = parse(refreshSchema, req, res);
  if (!data) return;
  revokeRefreshToken(data.refreshToken);
  res.json({ ok: true });
});

app.post("/api/auth/password/forgot", authLimiter, (req, res) => {
  const data = parse(forgotSchema, req, res);
  if (!data) return;
  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(data.email.toLowerCase());
  if (user) {
    const token = issuePasswordResetToken(user.id);
    return res.json({ ok: true, resetToken: token });
  }
  return res.json({ ok: true });
});

app.post("/api/auth/password/reset", authLimiter, async (req, res) => {
  const data = parse(resetSchema, req, res);
  if (!data) return;
  const userId = consumePasswordResetToken(data.token);
  if (!userId) return res.status(400).json({ error: "Invalid or expired reset token" });
  const hash = await bcrypt.hash(data.password, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, userId);
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/forum/threads", (_req, res) => {
  const rows = db
    .prepare(`
      SELECT t.id, t.tag, t.title, t.body, t.is_pinned AS isPinned, t.is_locked AS isLocked,
             t.created_at AS createdAt, t.updated_at AS updatedAt,
             u.id AS userId, u.name AS author,
             COUNT(r.id) AS replyCount
      FROM threads t
      JOIN users u ON u.id = t.user_id
      LEFT JOIN replies r ON r.thread_id = t.id AND r.is_deleted = 0
      WHERE t.is_deleted = 0
      GROUP BY t.id
      ORDER BY t.is_pinned DESC, t.updated_at DESC
    `)
    .all();
  res.json({ threads: rows });
});

app.get("/api/forum/threads/:threadId", (req, res) => {
  const threadId = Number(req.params.threadId);
  const thread = db
    .prepare(`
      SELECT t.id, t.tag, t.title, t.body, t.is_pinned AS isPinned, t.is_locked AS isLocked,
             t.created_at AS createdAt, t.updated_at AS updatedAt,
             u.id AS userId, u.name AS author
      FROM threads t
      JOIN users u ON u.id = t.user_id
      WHERE t.id = ? AND t.is_deleted = 0
    `)
    .get(threadId);
  if (!thread) {
    return res.status(404).json({ error: "Thread not found" });
  }
  const replies = db
    .prepare(`
      SELECT r.id, r.body, r.created_at AS createdAt, u.id AS userId, u.name AS author
      FROM replies r
      JOIN users u ON u.id = r.user_id
      WHERE r.thread_id = ? AND r.is_deleted = 0
      ORDER BY r.created_at ASC
    `)
    .all(threadId);
  return res.json({ thread: { ...thread, replies } });
});

app.post("/api/forum/threads", writeLimiter, requireAuth, (req, res) => {
  const data = parse(threadSchema, req, res);
  if (!data) return;
  const { tag, title, body } = data;
  const now = Date.now();
  const result = db
    .prepare(
      "INSERT INTO threads (tag, title, body, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .run(tag, title, body, req.user.id, now, now);
  return res.status(201).json({ threadId: result.lastInsertRowid });
});

app.post("/api/forum/threads/:threadId/replies", writeLimiter, requireAuth, (req, res) => {
  const threadId = Number(req.params.threadId);
  const data = parse(replySchema, req, res);
  if (!data) return;
  const exists = db
    .prepare("SELECT id, is_locked AS isLocked FROM threads WHERE id = ? AND is_deleted = 0")
    .get(threadId);
  if (!exists) {
    return res.status(404).json({ error: "Thread not found" });
  }
  if (exists.isLocked) return res.status(403).json({ error: "Thread is locked" });
  const now = Date.now();
  db.prepare("INSERT INTO replies (thread_id, body, user_id, created_at) VALUES (?, ?, ?, ?)").run(
    threadId,
    data.body,
    req.user.id,
    now,
  );
  db.prepare("UPDATE threads SET updated_at = ? WHERE id = ?").run(now, threadId);
  return res.status(201).json({ ok: true });
});

app.patch(
  "/api/forum/threads/:threadId/moderation",
  writeLimiter,
  requireAuth,
  requireRole(["admin", "moderator"]),
  (req, res) => {
    const threadId = Number(req.params.threadId);
    const schema = z.object({
      isPinned: z.boolean().optional(),
      isLocked: z.boolean().optional(),
      isDeleted: z.boolean().optional(),
    });
    const data = parse(schema, req, res);
    if (!data) return;

    const thread = db.prepare("SELECT id FROM threads WHERE id = ?").get(threadId);
    if (!thread) return res.status(404).json({ error: "Thread not found" });
    db.prepare(
      "UPDATE threads SET is_pinned = COALESCE(?, is_pinned), is_locked = COALESCE(?, is_locked), is_deleted = COALESCE(?, is_deleted), updated_at = ? WHERE id = ?",
    ).run(
      data.isPinned === undefined ? null : Number(data.isPinned),
      data.isLocked === undefined ? null : Number(data.isLocked),
      data.isDeleted === undefined ? null : Number(data.isDeleted),
      Date.now(),
      threadId,
    );
    return res.json({ ok: true });
  },
);

app.patch(
  "/api/forum/replies/:replyId/moderation",
  writeLimiter,
  requireAuth,
  requireRole(["admin", "moderator"]),
  (req, res) => {
    const replyId = Number(req.params.replyId);
    const schema = z.object({ isDeleted: z.boolean() });
    const data = parse(schema, req, res);
    if (!data) return;
    const r = db.prepare("SELECT id FROM replies WHERE id = ?").get(replyId);
    if (!r) return res.status(404).json({ error: "Reply not found" });
    db.prepare("UPDATE replies SET is_deleted = ? WHERE id = ?").run(Number(data.isDeleted), replyId);
    return res.json({ ok: true });
  },
);

app.patch("/api/admin/users/:userId/role", writeLimiter, requireAuth, requireRole(["admin"]), (req, res) => {
  const userId = Number(req.params.userId);
  const schema = z.object({ role: z.enum(["user", "moderator", "admin"]), isBanned: z.boolean().optional() });
  const data = parse(schema, req, res);
  if (!data) return;
  db.prepare("UPDATE users SET role = ?, is_banned = COALESCE(?, is_banned) WHERE id = ?").run(
    data.role,
    data.isBanned === undefined ? null : Number(data.isBanned),
    userId,
  );
  return res.json({ ok: true });
});

app.get("/api/feedback/:sectionId", requireAuth, (req, res) => {
  const sectionId = String(req.params.sectionId);
  const row = db
    .prepare(
      "SELECT section_id AS sectionId, vote, comment, created_at AS createdAt, updated_at AS updatedAt FROM feedback WHERE section_id = ? AND user_id = ?",
    )
    .get(sectionId, req.user.id);
  res.json({ feedback: row || null });
});

app.post("/api/feedback", writeLimiter, requireAuth, (req, res) => {
  const data = parse(feedbackSchema, req, res);
  if (!data) return;
  const { sectionId, vote, comment } = data;
  const now = Date.now();
  db.prepare(`
    INSERT INTO feedback (section_id, vote, comment, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(section_id, user_id)
    DO UPDATE SET vote = excluded.vote, comment = excluded.comment, updated_at = excluded.updated_at
  `).run(sectionId, vote ?? null, comment ?? "", req.user.id, now, now);

  return res.json({ ok: true });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`API running on http://localhost:${PORT}`);
});
