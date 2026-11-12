import mysql from "mysql2/promise";

const g = globalThis; // survives Next.js hot reloads
g._pools = g._pools || {};

function make(user, password) {
  return mysql.createPool({
    host: process.env.MYSQL_HOST,
    user,
    password,
    database: process.env.MYSQL_DB,
    connectionLimit: 5,
    dateStrings: true,
    decimalNumbers: true,
  });
}

// One MySQL account per application role, so MySQL's own GRANTs decide what
// each role may do. role comes from the verified session.
export function poolForRole(role) {
  const accounts = {
    ADMIN: [process.env.ADMIN_DB_USER, process.env.ADMIN_DB_PASS],
    SECURITY_ANALYST: [process.env.ANALYST_DB_USER, process.env.ANALYST_DB_PASS],
    DEVELOPER: [process.env.DEV_DB_USER, process.env.DEV_DB_PASS],
  };
  if (!accounts[role]) throw new Error("Unknown role");
  if (!g._pools[role]) g._pools[role] = make(...accounts[role]);
  return g._pools[role];
}

// used only by the login route; can run one stored procedure
export function authPool() {
  if (!g._pools.AUTH) {
    g._pools.AUTH = make(process.env.AUTH_DB_USER, process.env.AUTH_DB_PASS);
  }
  return g._pools.AUTH;
}

// Runs fn(conn) on the session's role connection. Sets @app_user first so the
// audit triggers in 08_triggers_audit.sql record WHO made the change.
export async function withDb(session, fn) {
  const conn = await poolForRole(session.role).getConnection();
  try {
    await conn.query("SET @app_user = ?", [session.email || session.name]);
    return await fn(conn);
  } finally {
    await conn.query("SET @app_user = NULL").catch(() => {});
    conn.release();
  }
}

// CALL returns [resultSet, okPacket]; this pulls out the first result set
export function firstSet(result) {
  const [rows] = result;
  return Array.isArray(rows?.[0]) ? rows[0] : rows;
}
