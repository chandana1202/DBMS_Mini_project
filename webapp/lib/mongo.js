import { MongoClient } from "mongodb";

const g = globalThis;

export async function mongo() {
  if (!g._mongo) {
    g._mongo = new MongoClient(process.env.MONGO_URI || "mongodb://localhost:27017", {
      serverSelectionTimeoutMS: 3000,
    }).connect();
  }
  try {
    const client = await g._mongo;
    return client.db(process.env.MONGO_DB || "supply_chain_nosql");
  } catch (e) {
    g._mongo = null; // let the next request retry
    throw e;
  }
}

// Every NoSQL write also leaves a document in audit_log
export async function mongoAudit(db, session, op, key, data) {
  await db.collection("audit_log").insertOne({
    collection: "analyst_notes",
    op,
    key,
    data,
    by: session.email,
    role: session.role,
    at: new Date(),
  });
}
