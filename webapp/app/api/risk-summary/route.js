import { guard, json, dbError } from "../../../lib/api";
import { withDb } from "../../../lib/db";

// All three roles have SELECT on v_project_risk_summary
export async function GET() {
  const { session, res } = await guard();
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT project_id, project, criticality, critical_cnt, high_cnt, medium_cnt, low_cnt,
                risk_score, RANK() OVER (ORDER BY risk_score DESC) AS risk_rank
         FROM v_project_risk_summary ORDER BY risk_score DESC, project`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
