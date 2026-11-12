import { guard, json, dbError } from "../../../../lib/api";
import { withDb } from "../../../../lib/db";

export async function GET() {
  const { session, res } = await guard(["ADMIN"]);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT u.user_id, u.full_name, u.email, u.role,
                (u.password_hash IS NOT NULL) AS can_log_in,
                COUNT(p.project_id) AS projects_owned
         FROM app_user u LEFT JOIN project p ON p.owner_id = u.user_id
         GROUP BY u.user_id ORDER BY u.user_id`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
