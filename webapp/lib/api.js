import { NextResponse } from "next/server";
import { getSession } from "./auth";

export const json = (data, status = 200) => NextResponse.json(data, { status });

// Application-level authorization for API routes.
// Returns { session } when allowed, or { res } holding a 401/403 response.
export async function guard(roles) {
  const session = await getSession();
  if (!session) return { res: json({ error: "Not logged in" }, 401) };
  if (roles && !roles.includes(session.role)) {
    return {
      res: json({ error: `Your role (${session.role}) cannot use this feature` }, 403),
    };
  }
  return { session };
}

// Turns MySQL errors into readable API responses
export function dbError(e) {
  // 1142 table denied, 1143 column denied, 1370 routine denied, 1044 db denied
  if ([1142, 1143, 1370, 1044].includes(e.errno)) {
    return json({ error: `MySQL refused this for your role: ${e.sqlMessage}` }, 403);
  }
  // 1644 = SIGNAL from a trigger/procedure, 3819 = CHECK failed,
  // 1062 = duplicate key, 1452 = foreign key missing
  if ([1644, 3819, 1062, 1452, 1366, 1265].includes(e.errno)) {
    return json({ error: e.sqlMessage }, 400);
  }
  if (e.name === "MongoServerSelectionError" || e.name === "MongoNetworkError") {
    return json({ error: "MongoDB is not reachable. Start mongod and run the migration script." }, 503);
  }
  if (e.code === 121) {
    return json({ error: "MongoDB schema validation rejected this document" }, 400);
  }
  console.error(e);
  return json({ error: e.sqlMessage || e.message || "Server error" }, 500);
}

export const STATUSES = ["OPEN", "IN_PROGRESS", "RESOLVED", "IGNORED"];
