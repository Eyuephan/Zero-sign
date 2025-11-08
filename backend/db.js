// backend/db.js
import 'dotenv/config';
import mysql from 'mysql2/promise';

if (!process.env.DB_PASS) {
  console.error('❌ DB_PASS fehlt in .env – bitte setzen!');
  process.exit(1);
}

const db = await mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS,                    // <-- muss definiert sein
  database: process.env.DB_NAME || 'zso_app',
  port: Number(process.env.DB_PORT || 3306),
  connectionLimit: 10,
});

export default db;
