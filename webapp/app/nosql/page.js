"use client";
import { useCallback, useEffect, useState } from "react";
import Shell, { useMe } from "../../components/Shell";
import { Panel, ErrorNote, Severity, Button, inputCls, api } from "../../components/ui";

export default function NoSql() {
  return (
    <Shell
      title="Dependency graph"
      intro="This page reads and writes MongoDB (supply_chain_nosql). Projects embed their direct dependencies, and $graphLookup follows depends_on links to build the full tree."
    >
      <Body />
    </Shell>
  );
}

function Body() {
  const me = useMe();
  const [cves, setCves] = useState([]);
  const [cve, setCve] = useState("CVE-2022-24999");
  const [hits, setHits] = useState(null);
  const [trees, setTrees] = useState(null);
  const [notes, setNotes] = useState(null);
  const [draft, setDraft] = useState({ text: "", tags: "" });
  const [editing, setEditing] = useState(null);
  const [err, setErr] = useState("");

  const loadNotes = useCallback(() => {
    api(`/api/nosql/notes?cve=${encodeURIComponent(cve)}`).then(setNotes).catch((e) => setErr(e.message));
  }, [cve]);

  useEffect(() => {
    api("/api/nosql/cves").then(setCves).catch((e) => setErr(e.message));
    api("/api/nosql/closure").then(setTrees).catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    setHits(null);
    api(`/api/nosql/exposure?cve=${encodeURIComponent(cve)}`).then(setHits).catch((e) => setErr(e.message));
    loadNotes();
  }, [cve, loadNotes]);

  async function addNote(e) {
    e.preventDefault();
    setErr("");
    try {
      await api("/api/nosql/notes", {
        method: "POST",
        body: JSON.stringify({ cve_id: cve, text: draft.text, tags: draft.tags.split(",") }),
      });
      setDraft({ text: "", tags: "" });
      loadNotes();
    } catch (e) {
      setErr(e.message);
    }
  }

  async function saveEdit() {
    setErr("");
    try {
      await api("/api/nosql/notes", { method: "PATCH", body: JSON.stringify({ id: editing.id, text: editing.text }) });
      setEditing(null);
      loadNotes();
    } catch (e) {
      setErr(e.message);
    }
  }

  async function del(id) {
    setErr("");
    try {
      await api(`/api/nosql/notes?id=${id}`, { method: "DELETE" });
      loadNotes();
    } catch (e) {
      setErr(e.message);
    }
  }

  const canChange = (n) => n.author === me.email || me.role === "ADMIN";

  return (
    <>
      <ErrorNote>{err}</ErrorNote>

      <div className="flex flex-wrap items-center gap-3">
        <label htmlFor="cvepick" className="text-[14px] font-medium">Vulnerability</label>
        <select id="cvepick" className={`${inputCls} w-auto font-mono`} value={cve} onChange={(e) => setCve(e.target.value)}>
          {cves.map((c) => (
            <option key={c._id} value={c._id}>{c._id} ({c.severity.toLowerCase()})</option>
          ))}
        </select>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Who is exposed" note="Read with $graphLookup + $filter + $min on depth">
          {!hits ? (
            <p className="text-sm text-muted">Loading…</p>
          ) : (
            <>
              <p className="text-[14px]">
                <Severity level={hits.vuln.severity} /> CVSS {hits.vuln.cvss}. Affects{" "}
                <span className="font-mono text-[13px]">{hits.vuln.affected.join(", ")}</span>.{" "}
                {hits.vuln.patches.length
                  ? `Fixed in ${hits.vuln.patches.map((p) => p.fixed_in).join(", ")}.`
                  : "No patch yet."}
              </p>
              {hits.hits.length ? (
                <ul className="mt-3 space-y-1 text-[14px]">
                  {hits.hits.map((h) => (
                    <li key={h._id}>
                      <b>{h._id}</b> <span className="text-muted">at depth {h.exposure_depth}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-3 text-[14px] text-muted">No project reaches this CVE.</p>
              )}
            </>
          )}
        </Panel>

        <Panel title="Analyst notes" note="Create, read, update and delete documents in analyst_notes">
          <form onSubmit={addNote} className="space-y-2">
            <label className="sr-only" htmlFor="note">New note</label>
            <textarea
              id="note"
              rows={2}
              className={`${inputCls} w-full`}
              placeholder={`What should the team know about ${cve}?`}
              value={draft.text}
              onChange={(e) => setDraft({ ...draft, text: e.target.value })}
            />
            <div className="flex gap-2">
              <input
                className={`${inputCls} w-full`}
                placeholder="Tags, comma separated (optional)"
                value={draft.tags}
                onChange={(e) => setDraft({ ...draft, tags: e.target.value })}
              />
              <Button className="whitespace-nowrap" disabled={!draft.text.trim()}>Add note</Button>
            </div>
          </form>
          <ul className="mt-4 divide-y divide-line">
            {(notes || []).map((n) => (
              <li key={n._id} className="py-2.5 text-[14px]">
                {editing?.id === n._id ? (
                  <div className="space-y-2">
                    <textarea className={`${inputCls} w-full`} rows={2} value={editing.text} onChange={(e) => setEditing({ ...editing, text: e.target.value })} />
                    <div className="flex gap-2">
                      <Button onClick={saveEdit}>Save note</Button>
                      <Button variant="quiet" onClick={() => setEditing(null)}>Cancel</Button>
                    </div>
                  </div>
                ) : (
                  <>
                    <p>{n.text}</p>
                    <p className="mt-1 flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
                      <span>{n.author}</span>
                      <span>{new Date(n.updated_at || n.created_at).toLocaleString()}</span>
                      {(n.tags || []).map((t) => (
                        <span key={t} className="rounded bg-paper px-1.5">{t}</span>
                      ))}
                      {canChange(n) && (
                        <>
                          <button className="text-accent underline" onClick={() => setEditing({ id: n._id, text: n.text })}>Edit</button>
                          <button className="text-crit underline" onClick={() => del(n._id)}>Delete</button>
                        </>
                      )}
                    </p>
                  </>
                )}
              </li>
            ))}
            {notes && !notes.length && <li className="py-2 text-[14px] text-muted">No notes on this CVE yet.</li>}
          </ul>
        </Panel>
      </div>

      <Panel title="Full dependency tree of each project" note="One $graphLookup per project. Numbers show how deep each package sits.">
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {(trees || []).map((t) => (
            <div key={t._id}>
              <p className="text-[14px] font-medium">{t._id} <span className="font-normal text-muted">({t.owner})</span></p>
              <ul className="mt-1.5 space-y-0.5 font-mono text-[12.5px]">
                {t.components.map((c) => (
                  <li key={c.id} style={{ paddingLeft: `${(c.depth - 1) * 14}px` }}>
                    <span className="text-muted">{c.depth}</span> {c.id}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
