// backend/auth.js
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "devsecret";

export const COOKIE_NAME = "zsi_token";
export const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax",
  secure: !!process.env.COOKIE_SECURE, // lokal false
  path: "/",                            // MUSS beim Setzen & Löschen identisch sein
  // domain: undefined,                 // für localhost NICHT setzen
};

export function issueToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

export function setLoginCookie(res, token) {
  res.cookie(COOKIE_NAME, token, { ...COOKIE_OPTS });
}

export function clearLoginCookie(res) {
  // Log, bevor wir löschen
  try {
    const prev = res.req?.cookies?.[COOKIE_NAME];
    console.log("[AUTH] clearLoginCookie() vorher, req.cookies.zsi_token present:", !!prev);
  } catch {}
  // Express macht korrektes Expires/Max-Age
  res.clearCookie(COOKIE_NAME, { ...COOKIE_OPTS });
  // Log, welche Header gesetzt wurden
  const sc = res.getHeader("Set-Cookie");
  console.log("[AUTH] clearLoginCookie() Set-Cookie Header:", sc);
}

export function verifyToken(req, res, next) {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) {
      return res.status(401).json({ error: "no token" });
    }
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}
