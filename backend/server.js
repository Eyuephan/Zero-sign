import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";

import harden from "./security.js";
import { verifyToken, clearLoginCookie, COOKIE_NAME } from "./auth.js";
import "./polyfill-webcrypto.js";
import webauthnRoutes from "./webauthn.js";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const HOST = process.env.HOST || "127.0.0.1";   // nur lokal binden (Apache proxied)
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.resolve(__dirname, "..", "public");

/** WICHTIG: hinter Reverse Proxy aktivieren, damit Secure/SameSite-Cookies funktionieren */
app.set("trust proxy", 1); // vertraue X-Forwarded-* von Apache

app.use(express.json());
app.use(cookieParser());
harden(app);

// optional: HTTP→HTTPS erzwingen (nur wenn Apache nicht schon redirectet)
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] === "http") {
    const host = req.headers.host;
    return res.redirect(301, `https://${host}${req.originalUrl}`);
  }
  next();
});

// Logging (behalten)
app.use((req, res, next) => {
  const started = Date.now();
  const hdr = (h) => (typeof req.headers[h] === "string" ? req.headers[h] : undefined);
  console.log(`\n=== ${new Date().toISOString()} ${req.method} ${req.url} ===`);
  console.log("Host:", hdr("host"), "UA:", hdr("user-agent"));
  if (req.method !== "GET") console.log("Body:", JSON.stringify(req.body).slice(0, 1000));
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

app.post("/logout", (req, res) => {
  console.log("[LOGOUT] POST /logout received");
  clearLoginCookie(res);
  return res.json({ ok: true });
});

app.get("/logout", (req, res) => {
  console.log("[LOGOUT] GET /logout received");
  clearLoginCookie(res);
  return res.redirect("/");
});

app.get("/debug/cookies", (req, res) => {
  const present = !!req.cookies?.[COOKIE_NAME];
  res.json({ cookiePresent: present, cookies: req.cookies });
});

webauthnRoutes(app);

/** Graceful shutdown (systemd stop/restart) */
const server = app.listen(PORT, HOST, () => {
  console.log(`ZSO running on http://${HOST}:${PORT}`);
});
const shutdown = (sig) => () => {
  console.log(`[${sig}] shutting down…`);
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
};
process.on("SIGTERM", shutdown("SIGTERM"));
process.on("SIGINT", shutdown("SIGINT"));

export default app; // optional, für Tests
