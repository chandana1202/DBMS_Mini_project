import { guard, json, dbError } from "../../../../lib/api";
import { withDb, firstSet } from "../../../../lib/db";

// Calls the stored procedure get_affected_projects(cve)
export async function GET(req) {
  const { session, res } = await guard(["SECURITY_ANALYST", "ADMIN"]);
  if (res) return res;
  const cve = new URL(req.url).searchParams.get("cve")?.trim().toUpperCase();
  if (!cve || !/^CVE-\d{4}-\d{4,}$/.test(cve)) {
    return json({ error: "Enter a CVE ID like CVE-2022-24999" }, 400);
  }
  try {
    const rows = await withDb(session, async (c) =>
      firstSet(await c.query("CALL get_affected_projects(?)", [cve]))
    );
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
