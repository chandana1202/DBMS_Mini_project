"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

const DEMO = [
  { email: "admin@example.com", role: "Admin", does: "everything, incl. audit log and users" },
  { email: "meera@example.com", role: "Security analyst", does: "all CVEs, remediation board, MongoDB notes" },
  { email: "asha@example.com", role: "Developer", does: "only WebShop, PaymentService, BlogEngine" },
  { email: "ravi@example.com", role: "Developer", does: "only AdminPortal, DataPipeline, InternalTools" },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    setBusy(false);
    if (res.ok) {
      const next = new URLSearchParams(window.location.search).get("next");
      router.push(next && next.startsWith("/") ? next : "/dashboard");
    } else setError((await res.json()).error || "Login failed");
  }

  return (
    <main className="grid min-h-screen md:grid-cols-[1.1fr_1fr]">
      <section className="flex flex-col justify-center bg-ink px-8 py-12 text-white md:px-14">
        <h1 className="max-w-[18ch] text-[34px] font-semibold leading-tight tracking-tight">
          See how one bad package reaches your projects.
        </h1>
        <p className="mt-4 max-w-[52ch] text-[15px] leading-relaxed text-white/75">
          Tracks projects, package versions, CVEs and patches, and traces each vulnerability
          through direct and indirect dependencies.
        </p>
        <ol className="mt-8 flex flex-wrap items-center gap-1.5 font-mono text-[13px]">
          <li className="rounded bg-white/10 px-2 py-1">express@4.16.0</li>
          <li className="text-white/50">›</li>
          <li className="rounded bg-white/10 px-2 py-1">body-parser@1.18.3</li>
          <li className="text-white/50">›</li>
          <li className="rounded bg-high px-2 py-1 text-white">qs@6.5.2</li>
        </ol>
        <p className="mt-2 text-[13px] text-white/60">CVE-2022-24999 reaches WebShop three levels deep.</p>
      </section>

      <section className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <form onSubmit={submit} className="space-y-4">
            <h2 className="text-[20px] font-semibold">Log in</h2>
            <label className="block text-[13px] font-medium">
              Email
              <input
                className="mt-1 w-full rounded border border-line bg-surface px-3 py-2 text-[15px]"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </label>
            <label className="block text-[13px] font-medium">
              Password
              <input
                className="mt-1 w-full rounded border border-line bg-surface px-3 py-2 text-[15px]"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>
            {error && <p role="alert" className="text-[13px] text-crit">{error}</p>}
            <button
              disabled={busy}
              className="w-full rounded bg-accent py-2 text-[15px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
            >
              {busy ? "Checking…" : "Log in"}
            </button>
          </form>

          <div className="mt-8 border-t border-line pt-5">
            <p className="text-[13px] font-medium">Demo accounts (password Demo@1234)</p>
            <ul className="mt-2 space-y-1.5">
              {DEMO.map((d) => (
                <li key={d.email}>
                  <button
                    type="button"
                    onClick={() => {
                      setEmail(d.email);
                      setPassword("Demo@1234");
                    }}
                    className="w-full rounded px-2 py-1.5 text-left text-[13px] hover:bg-surface"
                  >
                    <span className="font-medium">{d.role}</span>{" "}
                    <span className="text-muted">({d.email}) sees {d.does}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>
    </main>
  );
}
