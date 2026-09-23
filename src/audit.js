import { query } from "./db.js";

export async function logAudit(actorId, action, targetType, targetId, details = {}) {
  await query(
    `INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, created_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [actorId, action, targetType, targetId, JSON.stringify(details), Date.now()],
  );
}
