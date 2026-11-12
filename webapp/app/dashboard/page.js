"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import Shell, { useMe, roleName } from "../../components/Shell";
import { Panel, Table, ErrorNote, api } from "../../components/ui";

export default function Dashboard() {
  return (
    <Shell
      title="Overview"
      intro="Risk score = 10 per critical, 5 per high, 2 per medium and 1 per low CVE that reaches the project, directly or through other packages."
    >
      <Body />
    </Shell>
  );
}

function Body() {
  const me = useMe();
  const [risk, setRisk] = useState(null);
  const [check, setCheck] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api("/api/risk-summary").then(setRisk).catch((e) => setErr(e.message));
    api("/api/db-check").then(setCheck).catch((e) => setErr(e.message));
  }, []);

  const max = Math.max(1, ...(risk || []).map((r) => r.risk_score));

  return (
    <>
      <p className="text-[15px]">
        Signed in as <b>{me.name}</b>, {roleName(me.role).toLowerCase()}.{" "}
        {me.role === "DEVELOPER" && <Link className="text-accent underline" href="/my-projects">Open your projects</Link>}
        {me.role !== "DEVELOPER" && <Link className="text-accent underline" href="/analyst">Open the vulnerability board</Link>}
      </p>
      <ErrorNote>{err}</ErrorNote>

      <Panel title="Project risk" note="From the view v_project_risk_summary, ranked with RANK() OVER (…)">
        <Table
          rows={risk}
          rowKey={(r) => r.project_id}
          cols={[
            { key: "risk_rank", label: "Rank", right: true },
            { key: "project", label: "Project", render: (r) => <span className="font-medium">{r.project}</span> },
            { key: "criticality", label: "Business criticality", render: (r) => r.criticality.toLowerCase() },
            { key: "critical_cnt", label: "Critical", right: true },
            { key: "high_cnt", label: "High", right: true },
            { key: "medium_cnt", label: "Medium", right: true },
            {
              key: "risk_score",
              label: "Risk score",
              render: (r) => (
                <div className="flex items-center gap-2">
                  <span className="w-6 text-right tabular-nums">{r.risk_score}</span>
                  <span className="h-2 w-32 rounded bg-paper">
                    <span className="block h-2 rounded bg-ink" style={{ width: `${(r.risk_score / max) * 100}%` }} />
                  </span>
                </div>
              ),
            },
          ]}
        />
      </Panel>

      <Panel
        title="What your database account can do"
        note={
          check
            ? `The app connects to MySQL as ${check.account} for your role. Each line below was tried just now; MySQL decided the result.`
            : "Checking…"
        }
      >
        {check && (
          <ul className="divide-y divide-line">
            {check.probes.map((p) => (
              <li key={p.label} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 text-[14px]">
                <span
                  className={`w-16 shrink-0 text-[12.5px] font-semibold ${p.allowed ? "text-low" : "text-crit"}`}
                >
                  {p.allowed ? "Allowed" : "Denied"}
                </span>
                <span className="min-w-48">{p.label}</span>
                <code className="text-[12px] text-muted">{p.allowed ? p.sql : p.error}</code>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}
