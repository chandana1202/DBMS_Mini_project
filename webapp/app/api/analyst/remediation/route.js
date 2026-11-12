import { guard, json, dbError, STATUSES } from "../../../../lib/api";
import { withDb } from "../../../../lib/db";

const ROLES = ["SECURITY_ANALYST", "ADMIN"];

export async function GET() {
  const { session, res } = await guard(ROLES);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT * FROM v_remediation_board
         ORDER BY FIELD(status,'OPEN','IN_PROGRESS','IGNORED','RESOLVED'), cvss_score DESC`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}

// Change status and/or take ownership. Runs in a transaction; the audit
// trigger records the change with @app_user = the analyst's email.
export async function PATCH(req) {
  const { session, res } = await guard(ROLES);
  if (res) return res;
  const { remediation_id, status, assign_to_me } = await req.json();
  if (!Number.isInteger(remediation_id) || !STATUSES.includes(status)) {
    return json({ error: "remediation_id and a valid status are required" }, 400);
  }
  try {
    const changed = await withDb(session, async (c) => {
      await c.beginTransaction();
      try {
        const [r] = await c.query(
          `UPDATE remediation
           SET status = ?,
               resolved_at = IF(? = 'RESOLVED', COALESCE(resolved_at, NOW()), NULL),
               assigned_to = IF(?, ?, assigned_to)
           WHERE remediation_id = ?`,
          [status, status, assign_to_me ? 1 : 0, session.uid, remediation_id]
        );
        await c.commit();
        return r.affectedRows;
      } catch (e) {
        await c.rollback();
        throw e;
      }
    });
    if (!changed) return json({ error: "Remediation not found" }, 404);
    return json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}
