import { guard, json, dbError } from "../../../../lib/api";
import { withDb } from "../../../../lib/db";

export async function GET() {
  const { session, res } = await guard(["ADMIN"]);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT pv.version_id, CONCAT(pk.name, '@', pv.version_no) AS label, pk.ecosystem
         FROM package_version pv JOIN package pk ON pk.package_id = pv.package_id
         ORDER BY pk.name, pv.release_date`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
