// backend/webauthn.js
import "./polyfill-webcrypto.js"; // wichtig: vor @simplewebauthn/server laden
import crypto from "node:crypto";
import db from "./db.js";
import { issueToken, setLoginCookie } from "./auth.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const rpID   = process.env.RPID   || "localhost";
const origin = process.env.ORIGIN || "http://localhost:3000";

// Challenge-Caches
const pendingByEmail     = new Map(); // email -> { challenge, userId }
const pendingByChallenge = new Map(); // challenge -> { challenge, ts }

/* ---------- Helpers ---------- */

// Egal ob String/ArrayBuffer/Uint8Array/Buffer -> Buffer
function toBuf(x) {
  if (!x) return null;
  if (Buffer.isBuffer(x)) return x;
  if (typeof x === "string") return Buffer.from(x, "base64url");
  if (x instanceof ArrayBuffer) return Buffer.from(new Uint8Array(x));
  if (ArrayBuffer.isView(x)) return Buffer.from(x);
  return null;
}

/* ---------- DB-Helper ---------- */

async function getUserByEmail(email) {
  const [rows] = await db.query(
    "SELECT id, email, user_handle FROM users WHERE email=? LIMIT 1",
    [email]
  );
  const row = rows[0];
  if (!row) return null;

  if (!row.user_handle) {
    const newHandle = crypto.randomBytes(32);
    await db.query("UPDATE users SET user_handle=? WHERE id=?", [newHandle, row.id]);
    row.user_handle = newHandle;
    console.log("[DB] Auto-added user_handle for", row.email);
  }
  return row;
}

async function createUser(email) {
  const id = crypto.randomUUID();
  const userHandle = crypto.randomBytes(32);
  await db.query("INSERT INTO users (id, email, user_handle) VALUES (?,?,?)", [
    id, email, userHandle,
  ]);
  console.log("[DB] Neuer User:", email);
  return { id, email, user_handle: userHandle };
}

async function upsertUser(email) {
  const exist = await getUserByEmail(email);
  return exist || createUser(email);
}

async function listCreds(userId) {
  const [rows] = await db.query(
    "SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id=?",
    [userId]
  );
  return rows;
}

async function insertCred(userId, info) {
  // v10/v11 kompatibel
  let credID = toBuf(info.credentialID) ?? toBuf(info.credential?.id);
  let pubKey = toBuf(info.credentialPublicKey) ?? toBuf(info.credential?.publicKey);
  const counter = Number(info.counter ?? info.credential?.counter ?? 0) || 0;

  if (!credID || !pubKey) {
    console.error("[DB] insertCred: missing credID/pubKey", {
      hasID: !!credID, hasPK: !!pubKey, keys: Object.keys(info || {}),
    });
    throw new Error("insertCred: invalid credential payload");
  }

  console.log("[DB] insertCred decoded:", { cred_len: credID.length, pk_len: pubKey.length });

  await db.query(
    `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count)
     VALUES (?,?,?,?)`,
    [userId, credID, pubKey, counter]
  );
  console.log("[DB] Neues Credential gespeichert für:", userId);
}

async function updateSignCount(credentialId, newCounter) {
  await db.query(
    "UPDATE webauthn_credentials SET sign_count=? WHERE credential_id=?",
    [newCounter, credentialId]
  );
}

// Für usernameless Login: User + Credential per credential_id
async function getUserByCredentialId(credIdBuf) {
  const [rows] = await db.query(
    `SELECT u.id AS user_id, u.email, c.credential_id, c.public_key, c.sign_count
       FROM webauthn_credentials c
       JOIN users u ON u.id = c.user_id
      WHERE c.credential_id = ?
      LIMIT 1`,
    [credIdBuf]
  );
  return rows[0] || null;
}

/* ---------- Routes ---------- */
export default function webauthnRoutes(app) {

  /* ===== Registrierung (mit E-Mail) ===== */
  app.post("/register/start", async (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    console.log("[API] /register/start email:", email);
    if (!email) return res.status(400).json({ error: "email required" });

    try {
      const user = await upsertUser(email);
      const existing = await listCreds(user.id);

      // v10+/v11-sichere Signatur: user:{ id, name, displayName }
      const userIdBuf = Buffer.isBuffer(user.user_handle)
        ? user.user_handle
        : Buffer.from(user.user_handle);

      const options = await generateRegistrationOptions({
        rpName: "Zero Sign-On",
        rpID,
        user: {
          id: userIdBuf,
          name: email,
          displayName: email,
        },
        excludeCredentials: (existing || []).map(c => ({
          id: Buffer.from(c.credential_id),
          type: "public-key",
        })),
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        attestationType: "none",
      });

      console.log("[API] generateRegistrationOptions ok? challenge present:", !!options?.challenge);
      if (!options?.challenge) return res.status(500).json({ error: "options-failed" });

      pendingByEmail.set(email, { challenge: options.challenge, userId: user.id });
      res.json(options);
    } catch (e) {
      console.error("[ERROR] /register/start:", e);
      res.status(500).json({ error: "internal", detail: String(e) });
    }
  });

  app.post("/register/finish", async (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    console.log("[API] /register/finish email:", email);
    const p = pendingByEmail.get(email);
    if (!p) return res.status(400).json({ error: "no pending" });

    try {
      const v = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: p.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });

      console.log("[API] Verified:", v.verified, "keys:", Object.keys(v));
      if (!v.verified) return res.status(400).json({ error: "verification failed" });

      const ri = v.registrationInfo;
      let credIDBuf = null;
      let pubKeyBuf = null;
      let counter   = 0;

      if (ri) {
        // alt (v10…)
        if (ri.credentialID)        credIDBuf = toBuf(ri.credentialID);
        if (ri.credentialPublicKey) pubKeyBuf = toBuf(ri.credentialPublicKey);
        if (typeof ri.counter === "number") counter = ri.counter;

        // neu (v11…)
        if (ri.credential) {
          const c = ri.credential;
          if (!credIDBuf && c.id)        credIDBuf = toBuf(c.id);
          if (!pubKeyBuf && c.publicKey) pubKeyBuf = toBuf(c.publicKey);
          if (typeof c.counter === "number") counter = c.counter;
        }
      }

      if (!credIDBuf || !pubKeyBuf) {
        console.error("[API] registrationInfo incomplete", {
          hasRI: !!ri, riKeys: ri ? Object.keys(ri) : [],
        });
        return res.status(400).json({ error: "registrationInfo-missing" });
      }

      await insertCred(p.userId, {
        credentialID: credIDBuf,
        credentialPublicKey: pubKeyBuf,
        counter,
      });
      pendingByEmail.delete(email);

      const token = issueToken({ email, uid: p.userId });
      setLoginCookie(res, token);
      console.log("[API] Registration success -> cookie gesetzt");
      res.json({ ok: true });
    } catch (e) {
      console.error("[ERROR] /register/finish:", e);
      res.status(400).json({ error: "reg verify error", detail: String(e) });
    }
  });

  /* ===== Usernameless Login (ohne E-Mail) ===== */

  // Start: KEINE allowCredentials → Browser zeigt gespeicherte Passkeys an
  app.post("/login/start", async (_req, res) => {
    try {
      const options = await generateAuthenticationOptions({
        rpID,
        userVerification: "required",
      });
      console.log("[API] generateAuthenticationOptions ok? challenge present:", !!options?.challenge);
      if (!options?.challenge) return res.status(500).json({ error: "options-failed" });

      pendingByChallenge.set(options.challenge, { challenge: options.challenge, ts: Date.now() });
      res.json(options);
    } catch (e) {
      console.error("[ERROR] /login/start:", e);
      res.status(500).json({ error: "internal", detail: String(e) });
    }
  });

  // Finish: Nutzer anhand credential_id finden und Assertion prüfen
  app.post("/login/finish", async (req, res) => {
    console.log("==== [/login/finish] ====");

    // 1) Challenge aus /login/start (Client schickt sie zurück)
    const expectedChallenge = req.body?.expectedChallenge || null;
    const p = expectedChallenge ? pendingByChallenge.get(expectedChallenge) : null;
    console.log("[FIN] expectedChallenge:", expectedChallenge, "pending:", !!p);

    // 2) Pflichtfeld rawId
    const rawId = req.body?.rawId;
    if (!rawId) return res.status(400).json({ error: "missing rawId" });
    const credIdBuf = Buffer.from(rawId, "base64url");
    console.log("[FIN] credIdBuf len:", credIdBuf.length);

    // 3) Credential + User aus DB holen
    const rec = await getUserByCredentialId(credIdBuf);
    console.log("[FIN] rec found:", !!rec);
    if (!rec) return res.status(400).json({ error: "credential not found" });

    // 4) Authenticator für die Lib bauen
    const authenticator = {
      credentialID: Buffer.from(rec.credential_id),
      credentialPublicKey: Buffer.from(rec.public_key),
      counter: Number.isFinite(Number(rec.sign_count)) ? Number(rec.sign_count) : 0,
      transports: [],
    };
    console.log("[FIN] auth obj:", {
      credId_isBuf: Buffer.isBuffer(authenticator.credentialID),
      pubKey_isBuf: Buffer.isBuffer(authenticator.credentialPublicKey),
      counter: authenticator.counter,
    });

    // 5) Verify
    const verifyOpts = {
      response: req.body,
      expectedChallenge: p?.challenge || undefined,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    };
    console.log("[FIN] verifyOpts keys:", Object.keys(verifyOpts));

    try {
      const v = await verifyAuthenticationResponse(verifyOpts);
      console.log("[FIN] verified:", v.verified);
      if (!v.verified) return res.status(400).json({ error: "verification failed" });

      const newCounter = v?.authenticationInfo?.newCounter;
      if (Number.isFinite(Number(newCounter))) {
        await updateSignCount(rec.credential_id, Number(newCounter));
      }

      if (p) pendingByChallenge.delete(p.challenge);

      const token = issueToken({ email: rec.email, uid: rec.user_id });
      setLoginCookie(res, token);
      return res.json({ ok: true });
    } catch (e) {
      console.error("[FIN-ERROR] verify threw:", e);
      return res.status(400).json({ error: "auth verify error", detail: String(e) });
    }
  });
}
