/* ============================================================
   db.js — Veripher database (PostgreSQL)
   Uses the DATABASE_URL environment variable that Render provides.
   Creates the tables automatically on first run.
   ============================================================ */
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost'))
        ? false : { rejectUnauthorized: false }
});

async function init(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email       TEXT PRIMARY KEY,
      pass_hash   TEXT NOT NULL,
      balance_usd NUMERIC NOT NULL DEFAULT 0,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS orders (
      id         TEXT PRIMARY KEY,
      email      TEXT NOT NULL,
      cost_usd   NUMERIC NOT NULL,
      resale_usd NUMERIC NOT NULL,
      refunded   BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS invoices (
      order_id   TEXT PRIMARY KEY,
      email      TEXT NOT NULL,
      amount_usd NUMERIC NOT NULL,
      credited   BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  console.log('Database ready');
}

module.exports = { pool, init };
