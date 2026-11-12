import { guard, json } from "../../../lib/api";
import { withDb } from "../../../lib/db";

// Runs the same harmless probes for every role, using that role's MySQL account.
// MySQL decides ALLOWED/DENIED, which proves RBAC lives in the database.
// The UPDATE/DELETE probes use WHERE 1=0, so they never change data.
const PROBES = [
  { label: "Read the risk summary view", sql: "SELECT COUNT(*) n FROM v_project_risk_summary" },
  { label: "Read all vulnerabilities", sql: "SELECT COUNT(*) n FROM vulnerability" },
  { label: "Update remediation rows", sql: "UPDATE remediation SET status = status WHERE 1 = 0" },
  { label: "Delete vulnerabilities", sql: "DELETE FROM vulnerability WHERE 1 = 0" },
  { label: "Read user accounts", sql: "SELECT COUNT(*) n FROM app_user" },
  { label: "Read the audit log", sql: "SELECT COUNT(*) n FROM audit_log" },
];

export async function GET() {
  const { session, res } = await guard();
  if (res) return res;
  const out = await withDb(session, async (c) => {
    const results = [];
    for (const p of PROBES) {
      try {
        await c.query(p.sql);
        results.push({ ...p, allowed: true });
      } catch (e) {
        results.push({ ...p, allowed: false, error: e.sqlMessage || e.message });
      }
    }
    return results;
  });
  return json({ role: session.role, account: dbAccount(session.role), probes: out });
}

function dbAccount(role) {
  return {
    ADMIN: process.env.ADMIN_DB_USER,
    SECURITY_ANALYST: process.env.ANALYST_DB_USER,
    DEVELOPER: process.env.DEV_DB_USER,
  }[role];
}
