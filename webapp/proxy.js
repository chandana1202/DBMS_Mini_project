import { NextResponse } from "next/server";
import { verifyToken } from "./lib/auth";

// Which roles may open which pages. API routes do their own (stricter) checks
// in lib/api.js, and MySQL GRANTs are the final layer.
const PAGE_ROLES = {
  "/my-projects": ["DEVELOPER"],
  "/analyst": ["SECURITY_ANALYST", "ADMIN"],
  "/nosql": ["SECURITY_ANALYST", "ADMIN"],
  "/admin": ["ADMIN"],
};

export async function proxy(request) {
  const { pathname } = request.nextUrl;
  const session = await verifyToken(request.cookies.get("session")?.value);

  if (!session) {
    const url = new URL("/login", request.url);
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  const rule = Object.entries(PAGE_ROLES).find(([p]) => pathname.startsWith(p));
  if (rule && !rule[1].includes(session.role)) {
    return NextResponse.redirect(new URL("/forbidden", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/my-projects/:path*", "/analyst/:path*", "/nosql/:path*", "/admin/:path*"],
};
