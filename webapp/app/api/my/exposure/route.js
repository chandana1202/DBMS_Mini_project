import { guard, json, dbError } from "../../../../lib/api";
import { withDb, firstSet } from "../../../../lib/db";

export async function GET() {
  const { session, res } = await guard(["DEVELOPER"]);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) =>
      firstSet(await c.query("CALL get_my_exposure(?)", [session.uid]))
    );
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
