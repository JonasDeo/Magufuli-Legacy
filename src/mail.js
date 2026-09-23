import nodemailer from "nodemailer";

const APP_URL = process.env.APP_URL || "http://localhost:5173";

function getTransport() {
  const host = process.env.SMTP_HOST;
  if (!host) return null;

  return nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth:
      process.env.SMTP_USER && process.env.SMTP_PASS
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
  });
}

export async function sendPasswordResetEmail(email, token) {
  const resetUrl = `${APP_URL}/reset-password?token=${encodeURIComponent(token)}`;
  const from = process.env.SMTP_FROM || "noreply@magufuli.local";
  const subject = "Reset your Magufuli Legacy password";
  const text = `You requested a password reset.\n\nOpen this link to choose a new password (expires in 30 minutes):\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`;
  const html = `<p>You requested a password reset.</p><p><a href="${resetUrl}">Reset your password</a> (expires in 30 minutes).</p><p>If you did not request this, you can ignore this email.</p>`;

  const transport = getTransport();
  if (!transport) {
    // eslint-disable-next-line no-console
    console.log(`[mail] SMTP not configured. Password reset link for ${email}: ${resetUrl}`);
    return;
  }

  await transport.sendMail({ from, to: email, subject, text, html });
}
