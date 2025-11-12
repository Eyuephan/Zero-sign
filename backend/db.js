// backend/db.js
import "dotenv/config";
import mysql from "mysql2/promise";

// --- Minimal-Checks ---
if (!process.env.DB_PASS) {
  console.error("❌ DB_PASS fehlt in .env – bitte setzen!");
  process.exit(1);
}
if (!process.env.DB_USER) {
  console.error("❌ DB_USER fehlt in .env – bitte setzen! (nicht root!)");
  process.exit(1);
}
if (!process.env.DB_NAME) {
  console.error("❌ DB_NAME fehlt in .env – bitte setzen!");
  process.exit(1);
}

// Gemeinsame Optionen
const base = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_POOL || 10),
  queueLimit: 0,
  namedPlaceholders: true,
  charset: "utf8mb4",
  timezone: "Z", // UTC
};

// Socket bevorzugen, falls gesetzt
const pool =
  process.env.DB_SOCKET && process.env.DB_SOCKET.trim() !== ""
    ? await mysql.createPool({ ...base, socketPath: process.env.DB_SOCKET })
    : await mysql.createPool({
        ...base,
        host: process.env.DB_HOST || "127.0.0.1",
        port: Number(process.env.DB_PORT || 3306),
      });

// Kurzer Selbsttest beim Boot
try {
  const conn = await pool.getConnection();
  await conn.ping();
  conn.release();
  console.log(
    `✅ DB verbunden via ${process.env.DB_SOCKET ? "socket" : "tcp"} → ${
      process.env.DB_SOCKET || `${process.env.DB_HOST || "127.0.0.1"}:${process.env.DB_PORT || 3306}`
    } / DB=${process.env.DB_NAME}`
  );
} catch (err) {
  console.error("❌ DB-Verbindung fehlgeschlagen:", err?.message || err);
  process.exit(1);
}

// Helfer-Funktionen
export async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}
export async function exec(sql, params = []) {
  const [result] = await pool.execute(sql, params);
  return result;
}

export default pool;
