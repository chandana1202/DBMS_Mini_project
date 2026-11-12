import { guard, json, dbError } from "../../../../lib/api";
import { mongo } from "../../../../lib/mongo";

// READ: full dependency tree of every project with $graphLookup
// (the MongoDB equivalent of the recursive CTE)
export async function GET() {
  const { res } = await guard(["SECURITY_ANALYST", "ADMIN"]);
  if (res) return res;
  try {
    const db = await mongo();
    const docs = await db
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
            owner: 1,
            criticality: 1,
            direct_deps: 1,
            components: {
              $map: { input: "$closure", as: "c", in: { id: "$$c._id", depth: { $add: ["$$c.depth", 1] } } },
            },
          },
        },
        { $sort: { _id: 1 } },
      ])
      .toArray();
    // order each tree by depth, then name (done in JS so older MongoDB versions work)
    for (const d of docs) d.components.sort((a, b) => a.depth - b.depth || a.id.localeCompare(b.id));
    return json(docs);
  } catch (e) {
    return dbError(e);
  }
}
