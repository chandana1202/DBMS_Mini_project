import { guard, json, dbError } from "../../../../lib/api";
import { mongo } from "../../../../lib/mongo";

// READ: which projects reach a vulnerable component, and at what depth
export async function GET(req) {
  const { res } = await guard(["SECURITY_ANALYST", "ADMIN"]);
  if (res) return res;
  const cve = new URL(req.url).searchParams.get("cve");
  try {
    const db = await mongo();
    const vuln = await db.collection("vulnerabilities").findOne({ _id: cve });
    if (!vuln) return json({ error: "CVE not found in MongoDB" }, 404);
    const hits = await db
      .collection("projects")
      .aggregate([
        {
          $graphLookup: {
            from: "components",
            startWith: "$direct_deps",
            connectFromField: "depends_on",
            connectToField: "_id",
            as: "closure",
            depthField: "depth",
          },
        },
        {
          $project: {
            hits: { $filter: { input: "$closure", as: "c", cond: { $in: ["$$c._id", vuln.affected] } } },
          },
        },
        { $match: { "hits.0": { $exists: true } } },
        {
          $project: {
            exposure_depth: { $add: [{ $min: "$hits.depth" }, 1] },
            vulnerable_components: "$hits._id",
          },
        },
      ])
      .toArray();
    return json({ vuln, hits });
  } catch (e) {
    return dbError(e);
  }
}
