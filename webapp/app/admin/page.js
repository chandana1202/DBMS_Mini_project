"use client";
import { useCallback, useEffect, useState } from "react";
import Shell from "../../components/Shell";
import { Panel, Table, ErrorNote, Severity, Button, inputCls, api } from "../../components/ui";

export default function Admin() {
  return (
    <Shell title="Administration" intro="Register or remove vulnerabilities, see who can log in, and read the audit trail.">
      <Body />
    </Shell>
  );
}

function Body() {
  const [versions, setVersions] = useState([]);
  const [vulns, setVulns] = useState(null);
  const [users, setUsers] = useState(null);
  const [audit, setAudit] = useState(null);
  const [form, setForm] = useState({ cve_id: "CVE-2024-99999", cvss: "8.0", published: "2024-06-01", version_id: "3", description: "Demo bug in body-parser" });
  const [created, setCreated] = useState(null);
  const [err, setErr] = useState("");

  const load = useCallback(() => {
    api("/api/admin/vulnerabilities").then(setVulns).catch((e) => setErr(e.message));
    api("/api/admin/audit").then(setAudit).catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    api("/api/admin/versions").then(setVersions).catch((e) => setErr(e.message));
    api("/api/admin/users").then(setUsers).catch((e) => setErr(e.message));
    load();
  }, [load]);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  async function register(e) {
    e.preventDefault();
    setErr("");
    setCreated(null);
    try {
      setCreated(await api("/api/admin/vulnerabilities", { method: "POST", body: JSON.stringify(form) }));
      load();
    } catch (e) {
      setErr(e.message);
    }
  }

  async function remove(cve) {
    if (!confirm(`Delete ${cve}? Its affected versions, patches and remediation rows go with it.`)) return;
    setErr("");
    try {
      await api(`/api/admin/vulnerabilities?cve=${encodeURIComponent(cve)}`, { method: "DELETE" });
      load();
    } catch (e) {
      setErr(e.message);
    }
  }

  return (
    <>
      <ErrorNote>{err}</ErrorNote>

      <Panel
        title="Register a vulnerability"
        note="Runs register_vulnerability in one transaction. Triggers then set the severity from CVSS and open a remediation item for every project that reaches the version."
      >
        <form onSubmit={register} className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label className="text-[13px] font-medium">
            CVE ID
            <input className={`${inputCls} w-full mt-1 font-mono`} value={form.cve_id} onChange={set("cve_id")} required />
          </label>
          <label className="text-[13px] font-medium">
            CVSS score (0 to 10)
            <input className={`${inputCls} w-full mt-1`} type="number" step="0.1" min="0" max="10" value={form.cvss} onChange={set("cvss")} required />
          </label>
          <label className="text-[13px] font-medium">
            Published
            <input className={`${inputCls} w-full mt-1`} type="date" value={form.published} onChange={set("published")} required />
          </label>
          <label className="text-[13px] font-medium">
            Affected version
            <select className={`${inputCls} w-full mt-1`} value={form.version_id} onChange={set("version_id")}>
              {versions.map((v) => (
                <option key={v.version_id} value={v.version_id}>{v.label}</option>
              ))}
            </select>
          </label>
          <label className="text-[13px] font-medium sm:col-span-2 lg:col-span-3">
            Description
            <input className={`${inputCls} w-full mt-1`} value={form.description} onChange={set("description")} />
          </label>
          <div className="flex items-end">
            <Button className="w-full">Register vulnerability</Button>
          </div>
        </form>
        {created && (
          <p className="mt-4 text-[14px]">
            Saved <span className="font-mono">{created.vuln.cve_id}</span> with severity{" "}
            <Severity level={created.vuln.severity} /> (set by trigger).{" "}
            {created.opened.length
              ? `Remediation opened for ${created.opened.map((o) => o.project).join(", ")}.`
              : "No project uses this version, so nothing was opened."}
          </p>
        )}
      </Panel>

      <Panel title="Vulnerabilities">
        <Table
          rows={vulns}
          rowKey={(r) => r.cve_id}
          cols={[
            { key: "cve_id", label: "CVE", render: (r) => <span className="font-mono text-[13px]">{r.cve_id}</span> },
            { key: "severity", label: "Severity", render: (r) => <Severity level={r.severity} /> },
            { key: "cvss_score", label: "CVSS", right: true },
            { key: "published_date", label: "Published" },
            { key: "open_items", label: "Open items", right: true },
            { key: "x", label: "", render: (r) => <Button variant="danger" onClick={() => remove(r.cve_id)}>Delete</Button> },
          ]}
        />
      </Panel>

      <Panel title="Users" note="Passwords are stored as bcrypt hashes. Only the admin database account can read this table.">
        <Table
          rows={users}
          rowKey={(r) => r.user_id}
          cols={[
            { key: "full_name", label: "Name" },
            { key: "email", label: "Email" },
            { key: "role", label: "Role" },
            { key: "projects_owned", label: "Projects owned", right: true },
            { key: "can_log_in", label: "Password set", render: (r) => (r.can_log_in ? "Yes" : "No") },
          ]}
        />
      </Panel>

      <Panel title="Audit log" note="Written by triggers on vulnerability, remediation and project_dependency. Latest 100 changes.">
        <Table
          rows={audit}
          rowKey={(r) => r.log_id}
          cols={[
            { key: "changed_at", label: "When" },
            { key: "changed_by", label: "Who" },
            { key: "table_name", label: "Table" },
            { key: "operation", label: "Change" },
            { key: "record_id", label: "Row", right: true },
            { key: "old_data", label: "Before", render: (r) => <JsonCell v={r.old_data} /> },
            { key: "new_data", label: "After", render: (r) => <JsonCell v={r.new_data} /> },
          ]}
        />
      </Panel>
    </>
  );
}

function JsonCell({ v }) {
  if (!v) return <span className="text-muted">—</span>;
  const obj = typeof v === "string" ? JSON.parse(v) : v;
  return (
    <code className="block max-w-xs whitespace-pre-wrap break-words text-[12px] text-muted">
      {Object.entries(obj).map(([k, val]) => `${k}: ${val}`).join("\n")}
    </code>
  );
}
