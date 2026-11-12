import { guard, json, dbError } from "../../../../lib/api";
import { mongo } from "../../../../lib/mongo";

// READ: CVE list from the MongoDB copy (embedded affected[] and patches[])
export async function GET() {
  const { res } = await guard(["SECURITY_ANALYST", "ADMIN"]);
  if (res) return res;
  try {
    const db = await mongo();
    const docs = await db
      .collection("vulnerabilities")
      .find({}, { projection: { cve_id: 1, severity: 1, cvss: 1, affected: 1, patches: 1 } })
      .sort({ cvss: -1 })
      .toArray();
    return json(docs);
  } catch (e) {
    return dbError(e);
  }
}
