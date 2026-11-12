import { guard, json, dbError } from "../../../../lib/api";
import { withDb } from "../../../../lib/db";

export async function GET() {
  const { session, res } = await guard(["ADMIN"]);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT log_id, table_name, operation, record_id, old_data, new_data, changed_by, changed_at
         FROM audit_log ORDER BY log_id DESC LIMIT 100`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
