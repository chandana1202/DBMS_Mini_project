import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";

export const ROLES = ["ADMIN", "SECURITY_ANALYST", "DEVELOPER"];

const key = () => new TextEncoder().encode(process.env.JWT_SECRET);

export async function signToken(user) {
  return await new SignJWT({
    uid: user.user_id,
    name: user.full_name,
    email: user.email,
    role: user.role,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("2h")
    .sign(key());
}

export async function verifyToken(token) {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, key());
    return payload; // { uid, name, email, role, exp }
  } catch {
    return null; // tampered or expired
  }
}

export async function getSession() {
  const store = await cookies();
  return verifyToken(store.get("session")?.value);
}
