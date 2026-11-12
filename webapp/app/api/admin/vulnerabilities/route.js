import { guard, json, dbError } from "../../../../lib/api";
import { withDb, firstSet } from "../../../../lib/db";

// POST: register a CVE through the stored procedure register_vulnerability.
// Triggers then derive severity from CVSS and open remediation rows for every
// project that reaches the affected version (directly or indirectly).
export async function POST(req) {
  const { session, res } = await guard(["ADMIN"]);
  if (res) return res;
  const b = await req.json();
  const cve = String(b.cve_id || "").trim().toUpperCase();
  const cvss = Number(b.cvss);
  const versionId = Number(b.version_id);
  if (!cve || !b.published || !Number.isInteger(versionId) || Number.isNaN(cvss)) {
    return json({ error: "CVE ID, CVSS score, published date and affected version are required" }, 400);
  }
  try {
    const result = await withDb(session, async (c) => {
      const [{ new_vuln_id }] = firstSet(
        await c.query("CALL register_vulnerability(?, ?, ?, ?, ?)", [
          cve, b.description || null, cvss, b.published, versionId,
        ])
      );
      const [[vuln]] = await c.query(
        "SELECT cve_id, cvss_score, severity FROM vulnerability WHERE vuln_id = ?", [new_vuln_id]
      );
      const [opened] = await c.query(
        `SELECT p.name AS project, r.status FROM remediation r
         JOIN project p ON p.project_id = r.project_id WHERE r.vuln_id = ?`, [new_vuln_id]
      );
      return { vuln, opened };
    });
    return json(result, 201);
  } catch (e) {
    return dbError(e);
  }
}

// DELETE ?cve=...  ON DELETE CASCADE removes affected/patch/remediation rows;
// the audit trigger keeps a copy of what was deleted.
export async function DELETE(req) {
  const { session, res } = await guard(["ADMIN"]);
  if (res) return res;
  const cve = new URL(req.url).searchParams.get("cve");
  try {
    const n = await withDb(session, async (c) => {
      const [r] = await c.query("DELETE FROM vulnerability WHERE cve_id = ?", [cve]);
      return r.affectedRows;
    });
    if (!n) return json({ error: "No such CVE" }, 404);
    return json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}

// GET: list all CVEs with how many projects are still exposed
export async function GET() {
  const { session, res } = await guard(["ADMIN"]);
  if (res) return res;
  try {
    const rows = await withDb(session, async (c) => {
      const [r] = await c.query(
        `SELECT v.cve_id, v.severity, v.cvss_score, v.published_date,
                (SELECT COUNT(*) FROM remediation r
                 WHERE r.vuln_id = v.vuln_id AND r.status IN ('OPEN','IN_PROGRESS')) AS open_items
         FROM vulnerability v ORDER BY v.published_date DESC`
      );
      return r;
    });
    return json(rows);
  } catch (e) {
    return dbError(e);
  }
}
