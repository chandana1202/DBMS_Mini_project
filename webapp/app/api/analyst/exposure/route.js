import { guard, json, dbError } from "../../../../lib/api";
import { withDb } from "../../../../lib/db";

const ROLES = ["SECURITY_ANALYST", "ADMIN"];

// Every vulnerable project, direct or indirect, from the recursive-CTE view
export async function GET() {
  const { session, res } = await guard(ROLES);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT project, cve_id, severity, cvss_score, exposure, depth, dependency_path
         FROM v_vulnerable_projects ORDER BY cvss_score DESC, project`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
