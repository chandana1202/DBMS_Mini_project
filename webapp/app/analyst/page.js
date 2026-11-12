"use client";
import { useCallback, useEffect, useState } from "react";
import Shell, { useMe } from "../../components/Shell";
import { Panel, Table, ErrorNote, Severity, DepPath, Button, statusLabel, inputCls, api } from "../../components/ui";

const STATUSES = ["OPEN", "IN_PROGRESS", "RESOLVED", "IGNORED"];
const REPORTS = [
  { name: "critical", label: "Open critical and high" },
  { name: "fixes", label: "Fix recommendations" },
  { name: "unpatched", label: "No patch available" },
  { name: "outdated", label: "Outdated packages" },
];

export default function Analyst() {
  return (
    <Shell title="Vulnerabilities" intro="Every project, every CVE, and the remediation work in progress.">
      <Body />
    </Shell>
  );
}

function Body() {
  const me = useMe();
  const [exposure, setExposure] = useState(null);
  const [board, setBoard] = useState(null);
  const [cve, setCve] = useState("CVE-2022-24999");
  const [traced, setTraced] = useState(null);
  const [report, setReport] = useState("critical");
  const [reportRows, setReportRows] = useState(null);
  const [err, setErr] = useState("");

  const loadBoard = useCallback(() => {
    api("/api/analyst/remediation").then(setBoard).catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    api("/api/analyst/exposure").then(setExposure).catch((e) => setErr(e.message));
    loadBoard();
  }, [loadBoard]);

  useEffect(() => {
    setReportRows(null);
    api(`/api/analyst/reports?name=${report}`).then(setReportRows).catch((e) => setErr(e.message));
  }, [report]);

  async function trace(e) {
    e?.preventDefault();
    setErr("");
    setTraced(null);
    try {
      setTraced({ cve, rows: await api(`/api/analyst/affected?cve=${encodeURIComponent(cve)}`) });
    } catch (e) {
      setErr(e.message);
    }
  }

  async function update(row, status, assign_to_me = false) {
    setErr("");
    try {
      await api("/api/analyst/remediation", {
        method: "PATCH",
        body: JSON.stringify({ remediation_id: row.remediation_id, status, assign_to_me }),
      });
      loadBoard();
    } catch (e) {
      setErr(e.message);
    }
  }

  const knownCves = [...new Set((exposure || []).map((r) => r.cve_id))];

  return (
    <>
      <ErrorNote>{err}</ErrorNote>

      <Panel title="Trace a CVE" note="Calls the stored procedure get_affected_projects, which walks the dependency graph recursively.">
        <form onSubmit={trace} className="flex flex-wrap gap-2">
          <label className="sr-only" htmlFor="cve">CVE ID</label>
          <input id="cve" className={`${inputCls} w-56 font-mono`} value={cve} onChange={(e) => setCve(e.target.value)} />
          <Button>Trace</Button>
        </form>
        {knownCves.length > 0 && (
          <p className="mt-3 flex flex-wrap gap-1.5 text-[12.5px]">
            {knownCves.map((c) => (
              <button key={c} type="button" onClick={() => setCve(c)} className="rounded border border-line px-1.5 py-0.5 font-mono hover:bg-paper">
                {c}
              </button>
            ))}
          </p>
        )}
        {traced && (
          <div className="mt-4">
            {traced.rows.length === 0 ? (
              <p className="text-[14px] text-muted">No project reaches {traced.cve}.</p>
            ) : (
              <ul className="space-y-3">
                {traced.rows.map((r, i) => (
                  <li key={i} className="text-[14px]">
                    <p>
                      <b>{r.project}</b>{" "}
                      <span className="text-muted">{r.exposure.toLowerCase()}, depth {r.depth}</span>
                    </p>
                    <div className="mt-1">
                      <DepPath path={r.dependency_path} severity={exposure?.find((x) => x.cve_id === traced.cve)?.severity} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Panel>

      <Panel title="Remediation board" note="Updates run in a transaction, and the audit trigger records your email as the person who changed them.">
        <Table
          rows={board}
          rowKey={(r) => r.remediation_id}
          cols={[
            { key: "project", label: "Project" },
            { key: "cve_id", label: "CVE", render: (r) => <span className="font-mono text-[13px]">{r.cve_id}</span> },
            { key: "severity", label: "Severity", render: (r) => <Severity level={r.severity} /> },
            {
              key: "status",
              label: "Status",
              render: (r) => (
                <select
                  aria-label={`Status for ${r.project} ${r.cve_id}`}
                  className={`${inputCls} w-36 py-1`}
                  value={r.status}
                  onChange={(e) => update(r, e.target.value)}
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>{statusLabel(s)}</option>
                  ))}
                </select>
              ),
            },
            {
              key: "assignee",
              label: "Assignee",
              render: (r) =>
                r.assigned_to === me.uid ? (
                  "You"
                ) : (
                  <span className="flex items-center gap-2">
                    {r.assignee || <span className="text-muted">Nobody</span>}
                    <button onClick={() => update(r, r.status === "OPEN" ? "IN_PROGRESS" : r.status, true)} className="text-[12.5px] text-accent underline">
                      Take it
                    </button>
                  </span>
                ),
            },
          ]}
        />
      </Panel>

      <Panel
        title="Reports"
        note="Each tab reads one SQL view."
        actions={
          <div className="flex flex-wrap gap-1" role="tablist">
            {REPORTS.map((r) => (
              <button
                key={r.name}
                role="tab"
                aria-selected={report === r.name}
                onClick={() => setReport(r.name)}
                className={`rounded px-2 py-1 text-[13px] ${report === r.name ? "bg-ink text-white" : "hover:bg-paper"}`}
              >
                {r.label}
              </button>
            ))}
          </div>
        }
      >
        <Table
          rows={reportRows}
          cols={Object.keys(reportRows?.[0] || {}).map((k) => ({
            key: k,
            label: k.replaceAll("_", " "),
            render: k === "severity" ? (r) => <Severity level={r.severity} /> : k === "status" ? (r) => statusLabel(r.status) : undefined,
          }))}
        />
      </Panel>

      <Panel title="All exposures" note="From v_vulnerable_projects (recursive CTE with cycle protection).">
        <Table
          rows={exposure}
          cols={[
            { key: "project", label: "Project" },
            { key: "cve_id", label: "CVE", render: (r) => <span className="font-mono text-[13px]">{r.cve_id}</span> },
            { key: "severity", label: "Severity", render: (r) => <Severity level={r.severity} /> },
            { key: "exposure", label: "Exposure", render: (r) => r.exposure.toLowerCase() },
            { key: "dependency_path", label: "Path", render: (r) => <DepPath path={r.dependency_path} severity={r.severity} /> },
          ]}
        />
      </Panel>
    </>
  );
}
