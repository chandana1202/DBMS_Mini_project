"use client";
import { useCallback, useEffect, useState } from "react";
import Shell from "../../components/Shell";
import { Panel, Table, ErrorNote, Severity, DepPath, statusLabel, inputCls, api } from "../../components/ui";

const STATUSES = ["OPEN", "IN_PROGRESS", "RESOLVED", "IGNORED"];

export default function MyProjects() {
  return (
    <Shell
      title="My projects"
      intro="Only projects you own are shown. The database procedures get_my_remediation and update_my_remediation enforce this, not just the page."
    >
      <Body />
    </Shell>
  );
}

function Body() {
  const [items, setItems] = useState(null);
  const [exposure, setExposure] = useState(null);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState("");

  const load = useCallback(() => {
    api("/api/my/remediation").then(setItems).catch((e) => setErr(e.message));
    api("/api/my/exposure").then(setExposure).catch((e) => setErr(e.message));
  }, []);
  useEffect(load, [load]);

  async function setStatus(row, status) {
    setErr("");
    setSaved("");
    try {
      await api("/api/my/remediation", {
        method: "PATCH",
        body: JSON.stringify({ remediation_id: row.remediation_id, status }),
      });
      setSaved(`${row.project} / ${row.cve_id} is now ${statusLabel(status).toLowerCase()}.`);
      load();
    } catch (e) {
      setErr(e.message);
    }
  }

  return (
    <>
      <ErrorNote>{err}</ErrorNote>
      {saved && <p className="text-[13px] text-low">{saved}</p>}

      <Panel title="Fix list" note="Change the status as you work. Every change is written to the audit log with your email.">
        <Table
          rows={items}
          rowKey={(r) => r.remediation_id}
          empty="None of your projects has an open vulnerability."
          cols={[
            { key: "project", label: "Project" },
            { key: "cve_id", label: "CVE", render: (r) => <span className="font-mono text-[13px]">{r.cve_id}</span> },
            { key: "severity", label: "Severity", render: (r) => <Severity level={r.severity} /> },
            { key: "cvss_score", label: "CVSS", right: true },
            {
              key: "status",
              label: "Status",
              render: (r) => (
                <select
                  aria-label={`Status for ${r.project} ${r.cve_id}`}
                  className={`${inputCls} w-36 py-1`}
                  value={r.status}
                  onChange={(e) => setStatus(r, e.target.value)}
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>{statusLabel(s)}</option>
                  ))}
                </select>
              ),
            },
            { key: "resolved_at", label: "Resolved" },
          ]}
        />
      </Panel>

      <Panel title="How each vulnerability reaches you" note="Built by a recursive CTE over package dependencies (get_my_exposure).">
        <Table
          rows={exposure}
          empty="Nothing vulnerable in your dependency trees."
          cols={[
            { key: "project", label: "Project" },
            { key: "cve_id", label: "CVE", render: (r) => <span className="font-mono text-[13px]">{r.cve_id}</span> },
            { key: "exposure", label: "Exposure", render: (r) => `${r.exposure.toLowerCase()} (depth ${r.depth})` },
            { key: "dependency_path", label: "Path", render: (r) => <DepPath path={r.dependency_path} severity={r.severity} /> },
          ]}
        />
      </Panel>
    </>
  );
}
