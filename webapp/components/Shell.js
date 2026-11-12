"use client";
import { createContext, useContext, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

const MeContext = createContext(null);
export const useMe = () => useContext(MeContext);

const ROLE_NAME = { ADMIN: "Admin", SECURITY_ANALYST: "Security analyst", DEVELOPER: "Developer" };
export const roleName = (r) => ROLE_NAME[r] || r;

const LINKS = [
  { href: "/dashboard", label: "Overview", roles: ["ADMIN", "SECURITY_ANALYST", "DEVELOPER"] },
  { href: "/my-projects", label: "My projects", roles: ["DEVELOPER"] },
  { href: "/analyst", label: "Vulnerabilities", roles: ["SECURITY_ANALYST", "ADMIN"] },
  { href: "/nosql", label: "Dependency graph", roles: ["SECURITY_ANALYST", "ADMIN"] },
  { href: "/admin", label: "Administration", roles: ["ADMIN"] },
];

export default function Shell({ title, intro, children }) {
  const router = useRouter();
  const path = usePathname();
  const [me, setMe] = useState(null);

  useEffect(() => {
    fetch("/api/me").then(async (r) => {
      if (r.status === 401) router.replace("/login");
      else setMe(await r.json());
    });
  }, [router]);

  async function logout() {
    await fetch("/api/logout", { method: "POST" });
    router.replace("/login");
  }

  return (
    <MeContext.Provider value={me}>
      <div className="min-h-screen md:grid md:grid-cols-[220px_1fr]">
        <aside className="border-b border-line bg-surface md:min-h-screen md:border-b-0 md:border-r">
          <div className="px-5 py-4">
            <p className="text-[15px] font-semibold leading-tight">Supply-chain<br />vulnerability DB</p>
          </div>
          <nav className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:pb-0">
            {me &&
              LINKS.filter((l) => l.roles.includes(me.role)).map((l) => {
                const active = path === l.href;
                return (
                  <Link
                    key={l.href}
                    href={l.href}
                    className={`whitespace-nowrap rounded px-2.5 py-1.5 text-[14px] ${
                      active ? "bg-accent-soft font-medium text-accent" : "text-ink hover:bg-paper"
                    }`}
                  >
                    {l.label}
                  </Link>
                );
              })}
          </nav>
          {me && (
            <div className="hidden border-t border-line px-5 py-4 text-[13px] md:mt-6 md:block">
              <p className="font-medium">{me.name}</p>
              <p className="text-muted">{roleName(me.role)}</p>
              <button onClick={logout} className="mt-2 text-accent underline-offset-2 hover:underline">
                Log out
              </button>
            </div>
          )}
        </aside>

        <main className="mx-auto w-full max-w-6xl px-5 py-7 md:px-8">
          <div className="mb-6 flex items-start justify-between gap-4">
            <div>
              <h1 className="text-[26px] font-semibold tracking-tight">{title}</h1>
              {intro && <p className="mt-1 max-w-[70ch] text-[14px] text-muted">{intro}</p>}
            </div>
            {me && (
              <button onClick={logout} className="text-[13px] text-accent md:hidden">
                Log out
              </button>
            )}
          </div>
          {me ? <div className="space-y-6">{children}</div> : <p className="text-muted">Loading…</p>}
        </main>
      </div>
    </MeContext.Provider>
  );
}
