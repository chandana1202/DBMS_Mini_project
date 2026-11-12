import { guard, json, dbError } from "../../../../lib/api";
import { withDb } from "../../../../lib/db";

// Whitelisted views only - the name never goes into SQL directly
const REPORTS = {
  unpatched: "SELECT cve_id, severity, cvss_score, description FROM v_unpatched_vulnerabilities",
  fixes: "SELECT project, cve_id, severity, exposure, vulnerable_component, fixed_in FROM v_fix_recommendations ORDER BY project",
  outdated: "SELECT project, package, current_version, latest_version FROM v_outdated_packages ORDER BY project, package",
  critical: "SELECT project, cve_id, severity, cvss_score, status, assignee, due_date FROM v_critical_open_issues ORDER BY cvss_score DESC",
};

export async function GET(req) {
  const { session, res } = await guard(["SECURITY_ANALYST", "ADMIN"]);
  if (res) return res;
  const name = new URL(req.url).searchParams.get("name");
  if (!REPORTS[name]) return json({ error: "Unknown report" }, 400);
  try {
    const rows = await withDb(session, async (c) => (await c.query(REPORTS[name]))[0]);
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
