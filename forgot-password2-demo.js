// forgot-password2-demo.js
// Minimal "Forgot Password" demo flow for presentation purposes.
// NOTE: This is a simplified example. See security notes below.

import express from "express";
import crypto from "crypto";
import bcrypt from "bcrypt";

// --- Fake in-memory user store for demo --------------------------------------
const users = new Map(); // key: email, value: { passwordHash, resetToken, resetTokenExp }

// Seed a demo user
const demoEmail = "user@example.com";
const demoPasswordHash = await bcrypt.hash("SuperSecret123!", 10);
users.set(demoEmail, { passwordHash: demoPasswordHash });

// --- App setup ---------------------------------------------------------------
const app = express();
app.use(express.json());

// 1) Request reset: user submits email, we create a token and "send" it
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body || {};
  const user = users.get(email);
  // Always respond 200 to avoid email enumeration
  if (!user) return res.json({ message: "If the email exists, a reset link was sent." });

  // Generate token and set expiry (e.g., 15 min)
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 15 * 60 * 1000;

  user.resetToken = token;
  user.resetTokenExp = expiresAt;

  // In production: send an email with a link like:
  // https://yourapp.com/reset-password?token=<token>&email=<email>
  console.log(`[DEMO] Reset link for ${email}: http://localhost:3000/reset?token=${token}&email=${encodeURIComponent(email)}`);

  return res.json({ message: "If the email exists, a reset link was sent." });
});

// 2) Reset password: user clicks link, submits new password + token
app.post("/auth/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body || {};
  const user = users.get(email);
  if (!user || !user.resetToken || !user.resetTokenExp) {
    return res.status(400).json({ error: "Invalid or expired token." });
  }
  const isExpired = Date.now() > user.resetTokenExp;
  const isMatch = crypto.timingSafeEqual(Buffer.from(token), Buffer.from(user.resetToken));
  if (isExpired || !isMatch) {
    return res.status(400).json({ error: "Invalid or expired token." });
  }

  // Update password
  user.passwordHash = await bcrypt.hash(newPassword, 10);

  // Invalidate token
  delete user.resetToken;
  delete user.resetTokenExp;

  return res.json({ message: "Password reset successful." });
});

app.get("/health", (_, res) => res.send("OK"));
app.listen(3000, () => console.log("Demo server running on http://localhost:3000
