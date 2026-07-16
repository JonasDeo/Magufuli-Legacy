import { verifyToken } from "./auth.js";
import { db } from "./db.js";

export function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const payload = verifyToken(token);
    const user = db
      .prepare(
        "SELECT id, name, email, role, is_banned AS isBanned, created_at AS createdAt FROM users WHERE id = ?",
      )
      .get(payload.sub);
    if (!user || user.isBanned) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    req.user = user;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

export function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    return next();
  };
}
