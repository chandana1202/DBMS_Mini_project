import { ObjectId } from "mongodb";
import { guard, json, dbError } from "../../../../lib/api";
import { mongo, mongoAudit } from "../../../../lib/mongo";

const ROLES = ["SECURITY_ANALYST", "ADMIN"];

function toId(id) {
  try {
    return new ObjectId(String(id));
  } catch {
    return null;
  }
}

// Only the author or an ADMIN may change or delete a note
async function loadOwned(db, session, id) {
  const _id = toId(id);
  if (!_id) return { err: json({ error: "Bad note id" }, 400) };
  const note = await db.collection("analyst_notes").findOne({ _id });
  if (!note) return { err: json({ error: "Note not found" }, 404) };
  if (note.author !== session.email && session.role !== "ADMIN") {
    return { err: json({ error: "Only the author or an admin can change this note" }, 403) };
  }
  return { note };
}

// READ
export async function GET(req) {
  const { res } = await guard(ROLES);
  if (res) return res;
  const cve = new URL(req.url).searchParams.get("cve");
  try {
    const db = await mongo();
    const notes = await db
      .collection("analyst_notes")
      .find(cve ? { cve_id: cve } : {})
      .sort({ created_at: -1 })
      .toArray();
    return json(notes);
  } catch (e) {
    return dbError(e);
  }
}

// CREATE
export async function POST(req) {
  const { session, res } = await guard(ROLES);
  if (res) return res;
  const { cve_id, text, tags } = await req.json();
  if (!cve_id || !text?.trim()) return json({ error: "Pick a CVE and write a note" }, 400);
  try {
    const db = await mongo();
    const doc = {
      cve_id,
      text: text.trim(),
      author: session.email,
      created_at: new Date(),
    };
    const cleanTags = (tags || []).map((t) => String(t).trim()).filter(Boolean);
    if (cleanTags.length) doc.tags = cleanTags; // flexible schema: field only when needed
    const r = await db.collection("analyst_notes").insertOne(doc);
    await mongoAudit(db, session, "INSERT", String(r.insertedId), doc);
    return json({ _id: r.insertedId, ...doc }, 201);
  } catch (e) {
    return dbError(e);
  }
}

// UPDATE
export async function PATCH(req) {
  const { session, res } = await guard(ROLES);
  if (res) return res;
  const { id, text } = await req.json();
  if (!text?.trim()) return json({ error: "Note text cannot be empty" }, 400);
  try {
    const db = await mongo();
    const { note, err } = await loadOwned(db, session, id);
    if (err) return err;
    await db
      .collection("analyst_notes")
      .updateOne({ _id: note._id }, { $set: { text: text.trim(), updated_at: new Date() } });
    await mongoAudit(db, session, "UPDATE", String(note._id), { old: note.text, new: text.trim() });
    return json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}

// DELETE
export async function DELETE(req) {
  const { session, res } = await guard(ROLES);
  if (res) return res;
  const id = new URL(req.url).searchParams.get("id");
  try {
    const db = await mongo();
    const { note, err } = await loadOwned(db, session, id);
    if (err) return err;
    await db.collection("analyst_notes").deleteOne({ _id: note._id });
    await mongoAudit(db, session, "DELETE", String(note._id), { cve_id: note.cve_id, text: note.text });
    return json({ ok: true });
  } catch (e) {
    return dbError(e);
  }
}
