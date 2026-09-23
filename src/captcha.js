import jwt from "jsonwebtoken";

const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || process.env.JWT_SECRET || "dev-captcha-secret";

export function createCaptcha() {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const answer = a + b;
  const token = jwt.sign({ answer }, CAPTCHA_SECRET, { expiresIn: "5m" });
  return { question: `What is ${a} + ${b}?`, token };
}

export function verifyCaptcha(token, answer) {
  if (!token || answer === undefined || answer === null || answer === "") return false;
  try {
    const payload = jwt.verify(token, CAPTCHA_SECRET);
    return Number(answer) === payload.answer;
  } catch {
    return false;
  }
}
