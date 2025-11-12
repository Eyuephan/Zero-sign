// backend/auth.js
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "devsecret";
export const COOKIE_NAME = "zsi_token";

/** String-zu-Boolean sauber parsen */
function envBool(name, fallback = false) {
  const v = process.env[name];
  if (v == null) return fallback;
  return ["1","true","yes","on"].includes(String(v).toLowerCase());
}

/** HTTPS-Erkennung aus ORIGIN (empfohlen) */
const ORIGIN = process.env.ORIGIN || "";
const IS_HTTPS = /^https:/i.test(ORIGIN);

/** In Dev: lax + insecure; In Prod(HTTPS): none + secure */
function cookieOptsBase() {
  const secure = IS_HTTPS || envBool("COOKIE_SECURE", false);
  return {
    httpOnly: true,
    sameSite: secure ? "none" : "lax",  // SameSite=None NUR mit secure:true
    secure,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,    // 7 Tage
  };
}

export function issueToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

export function setLoginCookie(res, token) {
  const opts = cookieOptsBase();
  res.cookie(COOKIE_NAME, token, opts);
  // Debug: sicherstellen, dass der Header wirklich gesetzt ist
  const sc = res.get("Set-Cookie");
  console.log("[AUTH] setLoginCookie() Set-Cookie:", sc);
}

export function clearLoginCookie(res) {
  try {
    const prev = res.req?.cookies?.[COOKIE_NAME];
    console.log("[AUTH] clearLoginCookie() vorher vorhanden?", !!prev);
  } catch {}
  const opts = cookieOptsBase();
  res.clearCookie(COOKIE_NAME, opts);
  console.log("[AUTH] clearLoginCookie() Set-Cookie:", res.get("Set-Cookie"));
}

export function verifyToken(req, res, next) {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: "no token" });
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}
