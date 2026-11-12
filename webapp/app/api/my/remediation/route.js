import { guard, json, dbError, STATUSES } from "../../../../lib/api";
import { withDb, firstSet } from "../../../../lib/db";

// DEVELOPER only: remediation items of projects the logged-in user owns
export async function GET() {
  const { session, res } = await guard(["DEVELOPER"]);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) =>
      firstSet(await c.query("CALL get_my_remediation(?)", [session.uid]))
    );
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}

// The procedure itself refuses rows of projects the user does not own
export async function PATCH(req) {
  const { session, res } = await guard(["DEVELOPER"]);
  if (res) return res;
  const { remediation_id, status } = await req.json();
  if (!Number.isInteger(remediation_id) || !STATUSES.includes(status)) {
    return json({ error: "remediation_id and a valid status are required" }, 400);
  }
  try {
    await withDb(session, (c) =>
      c.query("CALL update_my_remediation(?, ?, ?)", [session.uid, remediation_id, status])
    );
    return json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}
