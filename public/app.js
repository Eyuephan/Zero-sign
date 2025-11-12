// public/app.js
import { startRegistration, startAuthentication } from
  "https://cdn.jsdelivr.net/npm/@simplewebauthn/browser@11.0.0/+esm"; 
const $ = (q) => document.querySelector(q);

function log(...args) {
  console.log(...args);
  const pre = $("#log");
  if (pre) pre.textContent += args.map(x => (typeof x === "object" ? JSON.stringify(x, null, 2) : x)).join(" ") + "\n";
}

async function logout() {
  try {
    log("[client] POST /logout ...");
    const r = await fetch("/logout", { method: "POST" });
    log("[client] /logout status", r.status);
    if (!r.ok) {
      log("[client] POST /logout failed, fallback GET /logout");
      window.location.href = "/logout";
      return;
    }
  } catch (e) {
    log("[client] POST /logout exception", String(e));
    window.location.href = "/logout";
    return;
  }
  try {
    const dbg = await fetch("/debug/cookies");
    log("[client] /debug/cookies after logout:", await dbg.json());
  } catch {}
  location.reload();
}

async function registerPasskey() {
  try {
    const email = $("#email").value.trim().toLowerCase();
    if (!email) return alert("Bitte E-Mail eingeben");
    log("[client] POST /register/start", { email });

    const r1 = await fetch("/register/start", {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ email }),
    });
    log("[client] /register/start status", r1.status);
    const options = await r1.json();
    log("→ options:", options);

    // v11: options in { optionsJSON } übergeben
    const att = await startRegistration({ optionsJSON: options });
    log("→ attestation keys:", Object.keys(att));
    att.email = email;

    const r2 = await fetch("/register/finish", {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify(att),
    });
    log("[client] /register/finish status", r2.status);
    if (!r2.ok) {
      const err = await r2.json().catch(()=>({}));
      alert("Fehler bei Registrierung: " + JSON.stringify(err));
      return;
    }
    location.reload();
  } catch (e) {
    console.error(e);
    alert("Fehler: " + e);
  }
}

async function loginPasskey() {
  try {
    const email = $("#email").value.trim().toLowerCase();
    if (!email) return alert("Bitte E-Mail eingeben");
    log("[client] POST /login/start", { email });

    const r1 = await fetch("/login/start", {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ email }),
    });
    log("[client] /login/start status", r1.status);
    const opts = await r1.json();
    log("→ auth options:", opts);

    // v11: options in { optionsJSON } übergeben
    const ass = await startAuthentication({ optionsJSON: opts });
    log("→ assertion keys:", Object.keys(ass));

    // Challenge für den Server mitschicken (damit er pendingByChallenge findet)
    ass.expectedChallenge = opts.challenge;
    ass.email = email;

    const r2 = await fetch("/login/finish", {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify(ass),
    });
    log("[client] /login/finish status", r2.status);
    if (!r2.ok) {
      const err = await r2.json().catch(()=>({}));
      alert("Fehler bei Login: " + JSON.stringify(err));
      return;
    }
    location.reload();
  } catch (e) {
    console.error(e);
    alert("Fehler: " + e);
  }
}

export async function checkLogin() {
  const s = $("#status");
  const a = $("#actions");
  try {
    const r = await fetch("/api/me");
    log("[client] GET /api/me status", r.status);
    if (!r.ok) throw 0;
    const d = await r.json();
    s.textContent = `✅ Eingeloggt als ${d.user.email}`;
    a.innerHTML = `<button id="logout" type="button">Logout</button>`;
    $("#logout").onclick = logout;
  } catch {
    s.textContent = "❌ Nicht eingeloggt.";
    a.innerHTML = `
      <input id="email" placeholder="email@example.com" />
      <button id="reg">Passkey registrieren</button>
      <button id="auth">Mit Passkey anmelden</button>
      <pre id="log"></pre>
    `;
    $("#reg").onclick = registerPasskey;
    $("#auth").onclick = loginPasskey;
  }
}

// Start
checkLogin();
