// Small presentational components shared by every page

const SEV = {
  CRITICAL: "bg-crit-soft text-crit border-crit/30",
  HIGH: "bg-high-soft text-high border-high/30",
  MEDIUM: "bg-med-soft text-med border-med/30",
  LOW: "bg-low-soft text-low border-low/30",
};
const SEV_BAR = { CRITICAL: "bg-crit", HIGH: "bg-high", MEDIUM: "bg-med", LOW: "bg-low" };

export function Severity({ level }) {
  if (!level) return null;
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 text-xs font-semibold ${SEV[level] || ""}`}>
      {level.charAt(0) + level.slice(1).toLowerCase()}
    </span>
  );
}

export function SeverityBar({ level }) {
  return <span aria-hidden className={`block w-1 self-stretch rounded-full ${SEV_BAR[level] || "bg-line"}`} />;
}

const STATUS_LABEL = { OPEN: "Open", IN_PROGRESS: "In progress", RESOLVED: "Resolved", IGNORED: "Ignored" };
export const statusLabel = (s) => STATUS_LABEL[s] || s;

// The dependency path "express@4.16.0 -> body-parser@1.18.3 -> qs@6.5.2" drawn
// as a chain. The last link is the vulnerable package, tinted by severity.
export function DepPath({ path, severity }) {
  const parts = String(path || "").split(" -> ");
  return (
    <ol className="flex flex-wrap items-center gap-1 font-mono text-[12.5px]">
      {parts.map((p, i) => {
        const last = i === parts.length - 1;
        return (
          <li key={i} className="flex items-center gap-1">
            <span
              className={`rounded px-1.5 py-0.5 ${
                last ? `${SEV[severity] || "bg-crit-soft text-crit"} border` : "bg-paper text-ink border border-line"
              }`}
            >
              {p}
            </span>
            {!last && <span className="text-muted" aria-label="depends on">›</span>}
          </li>
        );
      })}
    </ol>
  );
}

export function Panel({ title, note, children, actions }) {
  return (
    <section className="rounded-lg border border-line bg-surface">
      <header className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line px-5 py-3.5">
        <div>
          <h2 className="text-[15px] font-semibold">{title}</h2>
          {note && <p className="mt-0.5 text-[13px] text-muted">{note}</p>}
        </div>
        {actions}
      </header>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Table({ cols, rows, empty = "Nothing to show yet.", rowKey }) {
  if (!rows) return <p className="text-sm text-muted">Loading…</p>;
  if (!rows.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="-mx-5 overflow-x-auto">
      <table className="w-full text-left text-[13.5px]">
        <thead>
          <tr className="border-b border-line text-[12.5px] text-muted">
            {cols.map((c) => (
              <th key={c.key} className={`px-5 py-2 font-medium ${c.right ? "text-right" : ""}`}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={rowKey ? rowKey(r) : i} className="border-b border-line/70 last:border-0 align-top">
              {cols.map((c) => (
                <td key={c.key} className={`px-5 py-2.5 ${c.right ? "text-right tabular-nums" : ""}`}>
                  {c.render ? c.render(r) : r[c.key] ?? "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ErrorNote({ children }) {
  if (!children) return null;
  return (
    <p role="alert" className="rounded border border-crit/30 bg-crit-soft px-3 py-2 text-[13px] text-crit">
      {children}
    </p>
  );
}

export function Button({ variant = "primary", className = "", ...props }) {
  const styles = {
    primary: "bg-accent text-white hover:bg-accent/90",
    quiet: "border border-line bg-surface text-ink hover:bg-paper",
    danger: "border border-crit/40 bg-surface text-crit hover:bg-crit-soft",
  };
  return (
    <button
      className={`rounded px-3 py-1.5 text-[13.5px] font-medium disabled:opacity-50 ${styles[variant]} ${className}`}
      {...props}
    />
  );
}

export const inputCls =
  "rounded border border-line bg-surface px-2.5 py-1.5 text-[14px] text-ink placeholder:text-muted/70";

// fetch helper: returns parsed JSON or throws Error(message from API)
export async function api(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
