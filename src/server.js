import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { initDb, query } from "./db.js";
import {
  consumePasswordResetToken,
  issuePasswordResetToken,
  issueRefreshToken,
  revokeRefreshToken,
  rotateRefreshToken,
  signAccessToken,
} from "./auth.js";
import { requireAuth, requireRole } from "./middleware.js";
import { sendPasswordResetEmail } from "./mail.js";
import { createCaptcha, verifyCaptcha } from "./captcha.js";
import { logAudit } from "./audit.js";

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

const forumWriteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many forum posts. Please wait a minute." },
});

const captchaFields = {
  captchaToken: z.string().min(10),
  captchaAnswer: z.string().min(1).max(10),
  website: z.string().max(0).optional(),
};

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
  ...captchaFields,
});
const replySchema = z.object({
  body: z.string().min(1).max(3000),
  ...captchaFields,
});
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

async function issueAuthResponse(user) {
  const accessToken = signAccessToken(user);
  const refreshToken = await issueRefreshToken(user.id);
  return { user, accessToken, refreshToken };
}

function assertCaptcha(data, res) {
  if (data.website) {
    res.status(400).json({ error: "Invalid submission" });
    return false;
  }
  if (!verifyCaptcha(data.captchaToken, data.captchaAnswer)) {
    res.status(400).json({ error: "Captcha verification failed" });
    return false;
  }
  return true;
}

async function assertNotSpamming(userId, body, table) {
  const now = Date.now();
  const recent = await query(
    `SELECT id FROM ${table} WHERE user_id = $1 AND created_at > $2 LIMIT 1`,
    [userId, now - 30_000],
  );
  if (recent.rows.length > 0) {
    const err = new Error("Please wait before posting again");
    err.status = 429;
    throw err;
  }

  const duplicate = await query(
    `SELECT id FROM ${table} WHERE user_id = $1 AND body = $2 AND created_at > $3 LIMIT 1`,
    [userId, body, now - 60 * 60 * 1000],
  );
  if (duplicate.rows.length > 0) {
    const err = new Error("Duplicate content detected");
    err.status = 400;
    throw err;
  }
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.get("/api/captcha", (_req, res) => {
  res.json(createCaptcha());
});

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const data = parse(registerSchema, req, res);
  if (!data) return;
  const { name, email, password } = data;

  const existing = await query("SELECT id FROM users WHERE email = $1", [email.toLowerCase()]);
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const now = Date.now();
  const result = await query(
    "INSERT INTO users (name, email, password_hash, role, created_at) VALUES ($1, $2, $3, 'user', $4) RETURNING id, name, email, role, created_at AS \"createdAt\"",
    [name, email.toLowerCase(), passwordHash, now],
  );
  return res.status(201).json(await issueAuthResponse(result.rows[0]));
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const data = parse(loginSchema, req, res);
  if (!data) return;
  const { email, password } = data;

  const { rows } = await query(
    `SELECT id, name, email, role, is_banned AS "isBanned", password_hash, created_at AS "createdAt"
     FROM users WHERE email = $1`,
    [email.toLowerCase()],
  );
  const row = rows[0];
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
  return res.json(await issueAuthResponse(user));
});

app.post("/api/auth/refresh", authLimiter, async (req, res) => {
  const data = parse(refreshSchema, req, res);
  if (!data) return;
  const userId = await rotateRefreshToken(data.refreshToken);
  if (!userId) return res.status(401).json({ error: "Invalid refresh token" });
  const { rows } = await query(
    'SELECT id, name, email, role, created_at AS "createdAt" FROM users WHERE id = $1',
    [userId],
  );
  const user = rows[0];
  if (!user) return res.status(401).json({ error: "Invalid refresh token" });
  return res.json(await issueAuthResponse(user));
});

app.post("/api/auth/logout", async (req, res) => {
  const data = parse(refreshSchema, req, res);
  if (!data) return;
  await revokeRefreshToken(data.refreshToken);
  res.json({ ok: true });
});

app.post("/api/auth/password/forgot", authLimiter, async (req, res) => {
  const data = parse(forgotSchema, req, res);
  if (!data) return;
  const { rows } = await query("SELECT id, email FROM users WHERE email = $1", [data.email.toLowerCase()]);
  const user = rows[0];
  if (user) {
    const token = await issuePasswordResetToken(user.id);
    try {
      await sendPasswordResetEmail(user.email, token);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("[mail] Failed to send reset email:", err);
      return res.status(500).json({ error: "Failed to send reset email" });
    }
  }
  return res.json({ ok: true, message: "If your email exists, reset instructions were sent." });
});

app.post("/api/auth/password/reset", authLimiter, async (req, res) => {
  const data = parse(resetSchema, req, res);
  if (!data) return;
  const userId = await consumePasswordResetToken(data.token);
  if (!userId) return res.status(400).json({ error: "Invalid or expired reset token" });
  const hash = await bcrypt.hash(data.password, 10);
  await query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, userId]);
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/forum/threads", async (_req, res) => {
  const { rows } = await query(`
    SELECT t.id, t.tag, t.title, t.body, t.is_pinned AS "isPinned", t.is_locked AS "isLocked",
           t.created_at AS "createdAt", t.updated_at AS "updatedAt",
           u.id AS "userId", u.name AS author,
           COUNT(r.id)::int AS "replyCount"
    FROM threads t
    JOIN users u ON u.id = t.user_id
    LEFT JOIN replies r ON r.thread_id = t.id AND r.is_deleted = FALSE
    WHERE t.is_deleted = FALSE
    GROUP BY t.id, u.id, u.name
    ORDER BY t.is_pinned DESC, t.updated_at DESC
  `);
  res.json({ threads: rows });
});

app.get("/api/forum/threads/:threadId", async (req, res) => {
  const threadId = Number(req.params.threadId);
  const { rows: threadRows } = await query(
    `
    SELECT t.id, t.tag, t.title, t.body, t.is_pinned AS "isPinned", t.is_locked AS "isLocked",
           t.created_at AS "createdAt", t.updated_at AS "updatedAt",
           u.id AS "userId", u.name AS author
    FROM threads t
    JOIN users u ON u.id = t.user_id
    WHERE t.id = $1 AND t.is_deleted = FALSE
  `,
    [threadId],
  );
  const thread = threadRows[0];
  if (!thread) {
    return res.status(404).json({ error: "Thread not found" });
  }
  const { rows: replies } = await query(
    `
    SELECT r.id, r.body, r.created_at AS "createdAt", u.id AS "userId", u.name AS author
    FROM replies r
    JOIN users u ON u.id = r.user_id
    WHERE r.thread_id = $1 AND r.is_deleted = FALSE
    ORDER BY r.created_at ASC
  `,
    [threadId],
  );
  return res.json({ thread: { ...thread, replies } });
});

app.post("/api/forum/threads", forumWriteLimiter, requireAuth, async (req, res) => {
  const data = parse(threadSchema, req, res);
  if (!data) return;
  if (!assertCaptcha(data, res)) return;

  const { tag, title, body } = data;
  try {
    await assertNotSpamming(req.user.id, body, "threads");
  } catch (err) {
    return res.status(err.status || 400).json({ error: err.message });
  }

  const now = Date.now();
  const result = await query(
    "INSERT INTO threads (tag, title, body, user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    [tag, title, body, req.user.id, now, now],
  );
  return res.status(201).json({ threadId: result.rows[0].id });
});

app.post("/api/forum/threads/:threadId/replies", forumWriteLimiter, requireAuth, async (req, res) => {
  const threadId = Number(req.params.threadId);
  const data = parse(replySchema, req, res);
  if (!data) return;
  if (!assertCaptcha(data, res)) return;

  const { rows: existsRows } = await query(
    'SELECT id, is_locked AS "isLocked" FROM threads WHERE id = $1 AND is_deleted = FALSE',
    [threadId],
  );
  const exists = existsRows[0];
  if (!exists) {
    return res.status(404).json({ error: "Thread not found" });
  }
  if (exists.isLocked) return res.status(403).json({ error: "Thread is locked" });

  try {
    await assertNotSpamming(req.user.id, data.body, "replies");
  } catch (err) {
    return res.status(err.status || 400).json({ error: err.message });
  }

  const now = Date.now();
  await query("INSERT INTO replies (thread_id, body, user_id, created_at) VALUES ($1, $2, $3, $4)", [
    threadId,
    data.body,
    req.user.id,
    now,
  ]);
  await query("UPDATE threads SET updated_at = $1 WHERE id = $2", [now, threadId]);
  return res.status(201).json({ ok: true });
});

app.patch(
  "/api/forum/threads/:threadId/moderation",
  writeLimiter,
  requireAuth,
  requireRole(["admin", "moderator"]),
  async (req, res) => {
    const threadId = Number(req.params.threadId);
    const schema = z.object({
      isPinned: z.boolean().optional(),
      isLocked: z.boolean().optional(),
      isDeleted: z.boolean().optional(),
    });
    const data = parse(schema, req, res);
    if (!data) return;

    const { rows } = await query("SELECT id FROM threads WHERE id = $1", [threadId]);
    if (rows.length === 0) return res.status(404).json({ error: "Thread not found" });

    await query(
      `UPDATE threads SET
         is_pinned = COALESCE($1, is_pinned),
         is_locked = COALESCE($2, is_locked),
         is_deleted = COALESCE($3, is_deleted),
         updated_at = $4
       WHERE id = $5`,
      [
        data.isPinned === undefined ? null : data.isPinned,
        data.isLocked === undefined ? null : data.isLocked,
        data.isDeleted === undefined ? null : data.isDeleted,
        Date.now(),
        threadId,
      ],
    );

    await logAudit(req.user.id, "thread.moderation", "thread", threadId, data);
    return res.json({ ok: true });
  },
);

app.patch(
  "/api/forum/replies/:replyId/moderation",
  writeLimiter,
  requireAuth,
  requireRole(["admin", "moderator"]),
  async (req, res) => {
    const replyId = Number(req.params.replyId);
    const schema = z.object({ isDeleted: z.boolean() });
    const data = parse(schema, req, res);
    if (!data) return;

    const { rows } = await query("SELECT id FROM replies WHERE id = $1", [replyId]);
    if (rows.length === 0) return res.status(404).json({ error: "Reply not found" });

    await query("UPDATE replies SET is_deleted = $1 WHERE id = $2", [data.isDeleted, replyId]);
    await logAudit(req.user.id, "reply.moderation", "reply", replyId, data);
    return res.json({ ok: true });
  },
);

app.get("/api/admin/users", writeLimiter, requireAuth, requireRole(["admin"]), async (_req, res) => {
  const { rows } = await query(
    `SELECT id, name, email, role, is_banned AS "isBanned", created_at AS "createdAt"
     FROM users ORDER BY created_at DESC`,
  );
  res.json({ users: rows });
});

app.get("/api/admin/audit-logs", writeLimiter, requireAuth, requireRole(["admin"]), async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const { rows } = await query(
    `SELECT a.id, a.action, a.target_type AS "targetType", a.target_id AS "targetId",
            a.details, a.created_at AS "createdAt",
            u.id AS "actorId", u.name AS "actorName", u.email AS "actorEmail"
     FROM audit_logs a
     JOIN users u ON u.id = a.actor_id
     ORDER BY a.created_at DESC
     LIMIT $1`,
    [limit],
  );
  res.json({ logs: rows });
});

app.patch("/api/admin/users/:userId/role", writeLimiter, requireAuth, requireRole(["admin"]), async (req, res) => {
  const userId = Number(req.params.userId);
  const schema = z.object({ role: z.enum(["user", "moderator", "admin"]), isBanned: z.boolean().optional() });
  const data = parse(schema, req, res);
  if (!data) return;

  const { rows: beforeRows } = await query(
    'SELECT id, role, is_banned AS "isBanned" FROM users WHERE id = $1',
    [userId],
  );
  if (beforeRows.length === 0) return res.status(404).json({ error: "User not found" });
  const before = beforeRows[0];

  await query("UPDATE users SET role = $1, is_banned = COALESCE($2, is_banned) WHERE id = $3", [
    data.role,
    data.isBanned === undefined ? null : data.isBanned,
    userId,
  ]);

  await logAudit(req.user.id, "user.role_update", "user", userId, {
    before: { role: before.role, isBanned: before.isBanned },
    after: { role: data.role, isBanned: data.isBanned ?? before.isBanned },
  });

  return res.json({ ok: true });
});

app.get("/api/feedback/:sectionId", requireAuth, async (req, res) => {
  const sectionId = String(req.params.sectionId);
  const { rows } = await query(
    `SELECT section_id AS "sectionId", vote, comment, created_at AS "createdAt", updated_at AS "updatedAt"
     FROM feedback WHERE section_id = $1 AND user_id = $2`,
    [sectionId, req.user.id],
  );
  res.json({ feedback: rows[0] || null });
});

app.post("/api/feedback", writeLimiter, requireAuth, async (req, res) => {
  const data = parse(feedbackSchema, req, res);
  if (!data) return;
  const { sectionId, vote, comment } = data;
  const now = Date.now();
  await query(
    `
    INSERT INTO feedback (section_id, vote, comment, user_id, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (section_id, user_id)
    DO UPDATE SET vote = EXCLUDED.vote, comment = EXCLUDED.comment, updated_at = EXCLUDED.updated_at
  `,
    [sectionId, vote ?? null, comment ?? "", req.user.id, now, now],
  );

  return res.json({ ok: true });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      // eslint-disable-next-line no-console
      console.log(`API running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });
