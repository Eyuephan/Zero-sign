// backend/server.js
import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";

import harden from "./security.js";
import { verifyToken, clearLoginCookie, COOKIE_NAME } from "./auth.js";
import webauthnRoutes from "./webauthn.js";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.resolve(__dirname, "..", "public");

app.use(express.json());
app.use(cookieParser());
harden(app);

// 🔎 sehr ausführlicher Logger
app.use((req, res, next) => {
  const started = Date.now();
  const hdr = (h) => (typeof req.headers[h] === "string" ? req.headers[h] : undefined);
  console.log(`\n=== ${new Date().toISOString()} ${req.method} ${req.url} ===`);
  console.log("Host:", hdr("host"), "UA:", hdr("user-agent"));
  if (req.method !== "GET") {
    console.log("Body:", JSON.stringify(req.body).slice(0, 1000));
  }
  console.log("Cookies in:", req.cookies);
  res.on("finish", () => {
    const sc = res.getHeader("Set-Cookie");
    console.log("→ Status:", res.statusCode, "Set-Cookie:", sc, "Time:", Date.now() - started, "ms");
  });
  next();
});

app.use(express.static(PUBLIC_DIR, { index: false }));
app.get("/", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

app.get("/api/health", (_req, res) => res.json({ status: "ok" }));
app.get("/api/me", verifyToken, (req, res) => res.json({ user: req.user }));

// 🔹 Logout (POST) – serverseitig Cookie killen
app.post("/logout", (req, res) => {
  console.log("[LOGOUT] POST /logout received");
  clearLoginCookie(res);
  return res.json({ ok: true });
});

// 🔹 Logout (GET) – Fallback ohne JS
app.get("/logout", (req, res) => {
  console.log("[LOGOUT] GET /logout received");
  clearLoginCookie(res);
  return res.redirect("/");
});

// 🔹 Debug: zeigt, ob Cookie laut Server ankam
app.get("/debug/cookies", (req, res) => {
  const present = !!req.cookies?.[COOKIE_NAME];
  res.json({ cookiePresent: present, cookies: req.cookies });
});

webauthnRoutes(app);

app.listen(PORT, () => console.log(`ZSO running on http://localhost:${PORT}`));
