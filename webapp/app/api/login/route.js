import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { authPool } from "../../../lib/db";
import { signToken } from "../../../lib/auth";

export async function POST(req) {
  const { email, password } = await req.json();
  const bad = () =>
    NextResponse.json({ error: "Wrong email or password" }, { status: 401 });

  if (!email || !password) return bad();

  // app_auth can run ONLY this procedure (sql/13_auth_login.sql)
  const [result] = await authPool().query("CALL auth_lookup(?)", [email.trim().toLowerCase()]);
  const user = result[0]?.[0];
  if (!user || !user.password_hash) return bad();

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return bad();

  const token = await signToken(user);
  const res = NextResponse.json({ name: user.full_name, role: user.role });
  res.cookies.set("session", token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 2,
    secure: process.env.NODE_ENV === "production",
  });
  return res;
}
