// Run in mongosh:   mongosh nosql/queries.js     (or paste into Compass > mongosh)
// Data comes from nosql/migrate_mysql_to_mongo.py
db = db.getSiblingDB("supply_chain_nosql");

// ======================= READ =======================

// N1: direct dependencies of a project
printjson(db.projects.findOne({ _id: "WebShop" }, { direct_deps: 1 }));

// N2: the equivalent of the recursive CTE - transitive closure with $graphLookup.
// Cycle protection is built in: $graphLookup tracks visited documents.
printjson(db.projects.aggregate([
  { $graphLookup: { from: "components", startWith: "$direct_deps",
      connectFromField: "depends_on", connectToField: "_id",
      as: "closure", depthField: "depth" } },
  { $project: { owner: 1, closure_size: { $size: "$closure" } } }
]).toArray());

// N3: projects exposed to one CVE (direct or indirect), with depth
var affected = db.vulnerabilities.findOne({ _id: "CVE-2022-24999" }).affected;
printjson(db.projects.aggregate([
  { $graphLookup: { from: "components", startWith: "$direct_deps",
      connectFromField: "depends_on", connectToField: "_id",
      as: "closure", depthField: "depth" } },
  { $project: { hits: { $filter: { input: "$closure", as: "c",
      cond: { $in: ["$$c._id", affected] } } } } },
  { $match: { "hits.0": { $exists: true } } },
  { $project: { exposure_depth: { $add: [{ $min: "$hits.depth" }, 1] },
                vulnerable_component: "$hits._id" } }
]).toArray());

// N4: unpatched vulnerabilities (expect CVE-2023-25577)
printjson(db.vulnerabilities.find({ patches: { $size: 0 } }, { cve_id: 1, severity: 1 }).toArray());

// N5: count CVEs per severity
printjson(db.vulnerabilities.aggregate([
  { $group: { _id: "$severity", count: { $sum: 1 }, avg_cvss: { $avg: "$cvss" } } },
  { $sort: { count: -1 } }
]).toArray());

// N6: open critical/high issues (join with $lookup)
printjson(db.remediation.aggregate([
  { $match: { status: { $in: ["OPEN", "IN_PROGRESS"] } } },
  { $lookup: { from: "vulnerabilities", localField: "cve_id", foreignField: "_id", as: "v" } },
  { $unwind: "$v" },
  { $match: { "v.severity": { $in: ["CRITICAL", "HIGH"] } } },
  { $project: { project: 1, cve_id: 1, severity: "$v.severity", status: 1 } }
]).toArray());

// N7: notes for one CVE, newest first
printjson(db.analyst_notes.find({ cve_id: "CVE-2021-44228" }).sort({ created_at: -1 }).toArray());

// ======================= UPDATE =======================

// U1: change a remediation status and write an audit entry
db.remediation.updateOne({ project: "WebShop", cve_id: "CVE-2022-24999" },
                         { $set: { status: "IN_PROGRESS" } });
db.audit_log.insertOne({ collection: "remediation", op: "UPDATE",
  key: "WebShop/CVE-2022-24999", new: { status: "IN_PROGRESS" }, by: "mongosh", at: new Date() });

// U2: add a tag to every note on a CVE ($addToSet avoids duplicates)
db.analyst_notes.updateMany({ cve_id: "CVE-2021-44228" }, { $addToSet: { tags: "reviewed" } });

// U3: edit one note's text
var note = db.analyst_notes.findOne({ cve_id: "CVE-2023-25577" });
db.analyst_notes.updateOne({ _id: note._id },
  { $set: { text: "No upstream patch. Workaround: cap multipart size at 1 MB.", updated_at: new Date() } });

// U4: schema validation in action - this update is REJECTED (severity not in the enum)
try {
  db.vulnerabilities.updateOne({ _id: "CVE-2023-25577" }, { $set: { severity: "SUPER_HIGH" } });
} catch (e) { print("Rejected by $jsonSchema: " + e.message); }

// ======================= DELETE =======================

// D1: insert a temporary note, then delete it by _id
var tmp = db.analyst_notes.insertOne({ cve_id: "CVE-2023-26159", text: "temporary note",
                                       author: "mongosh", created_at: new Date() });
printjson(db.analyst_notes.deleteOne({ _id: tmp.insertedId }));          // { deletedCount: 1 }

// D2: delete the audit entries written from mongosh in this demo
printjson(db.audit_log.deleteMany({ by: "mongosh" }));

// D3: remove one field from a document ($unset is a "partial delete")
db.vulnerabilities.updateOne({ _id: "CVE-2023-26159" }, { $unset: { description: "" } });

// ======================= TRANSACTION =======================
// N8: multi-document transaction. MongoDB needs a REPLICA SET for this.
// To try it locally:  mongod --replSet rs0   then in mongosh:  rs.initiate()
try {
  const session = db.getMongo().startSession();
  const s = session.getDatabase("supply_chain_nosql");
  session.startTransaction();
  s.remediation.updateOne({ project: "WebShop", cve_id: "CVE-2021-23337" }, { $set: { status: "RESOLVED" } });
  s.audit_log.insertOne({ collection: "remediation", op: "UPDATE",
    key: "WebShop/CVE-2021-23337", new: { status: "RESOLVED" }, by: "mongosh", at: new Date() });
  session.commitTransaction();          // both writes, or neither
  session.endSession();
  print("Transaction committed");
} catch (e) {
  print("Transaction skipped (standalone server, not a replica set): " + e.message);
}
