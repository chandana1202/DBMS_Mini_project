import { guard, json } from "../../../lib/api";

export async function GET() {
  const { session, res } = await guard();
  if (res) return res;
  return json({ uid: session.uid, name: session.name, email: session.email, role: session.role });
}
