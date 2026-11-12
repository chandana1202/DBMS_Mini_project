// End-to-end checks of authentication and role-based access through the API.
// Start the app first (npm run dev), then in another terminal: npm run test:api
// MongoDB checks are reported separately because they need mongod running.
const BASE = process.env.BASE_URL || "http://localhost:3000";
const PW = "Demo@1234";
let pass = 0, fail = 0;

async function login(email, password = PW) {
  const r = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const cookie = (r.headers.get("set-cookie") || "").split(";")[0];
  return { status: r.status, cookie };
}

async function call(cookie, method, path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", cookie },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "manual",
  });
  let data = null;
  try { data = await r.json(); } catch {}
  return { status: r.status, data };
}

function check(name, cond, extra = "") {
  if (cond) pass++; else fail++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  " + extra : ""}`);
}

// ---- authentication ----
check("wrong password is rejected", (await login("asha@example.com", "nope")).status === 401);
check("unknown email is rejected", (await login("x@example.com")).status === 401);
check("API without a session returns 401", (await call("", "GET", "/api/risk-summary")).status === 401);
const page = await fetch(`${BASE}/admin`, { redirect: "manual" });
check("protected page without a session redirects to /login", [307, 308].includes(page.status) && page.headers.get("location")?.includes("/login"));

const dev = (await login("asha@example.com")).cookie;
const dev2 = (await login("ravi@example.com")).cookie;
const ana = (await login("meera@example.com")).cookie;
const adm = (await login("admin@example.com")).cookie;
check("all four demo users can log in", dev && dev2 && ana && adm);

// ---- developer ----
const mine = await call(dev, "GET", "/api/my/remediation");
check("developer sees own remediation", mine.status === 200 && mine.data.every((r) => ["WebShop", "PaymentService", "BlogEngine"].includes(r.project)),
  `(${mine.data?.length} rows)`);
const ravis = await call(dev2, "GET", "/api/my/remediation");
const notMine = ravis.data[0].remediation_id;
const steal = await call(dev, "PATCH", "/api/my/remediation", { remediation_id: notMine, status: "IGNORED" });
check("developer cannot update another owner's item (procedure refuses)", steal.status === 400, steal.data?.error);
check("developer blocked from analyst API", (await call(dev, "GET", "/api/analyst/exposure")).status === 403);
check("developer blocked from admin API", (await call(dev, "GET", "/api/admin/audit")).status === 403);
const devPage = await fetch(`${BASE}/admin`, { headers: { cookie: dev }, redirect: "manual" });
check("developer opening /admin is sent to /forbidden", devPage.headers.get("location")?.includes("/forbidden"));
const dc = await call(dev, "GET", "/api/db-check");
check("MySQL itself denies developer reading vulnerability table",
  dc.data.probes.find((p) => p.label === "Read all vulnerabilities").allowed === false);

// ---- analyst ----
const trace = await call(ana, "GET", "/api/analyst/affected?cve=CVE-2022-24999");
check("analyst traces CVE through recursive procedure", trace.status === 200 && trace.data[0]?.depth === 3, trace.data[0]?.dependency_path);
const board = await call(ana, "GET", "/api/analyst/remediation");
const item = board.data[0];
const upd = await call(ana, "PATCH", "/api/analyst/remediation", { remediation_id: item.remediation_id, status: "IN_PROGRESS", assign_to_me: true });
check("analyst updates remediation", upd.status === 200);
check("analyst blocked from admin API", (await call(ana, "GET", "/api/admin/users")).status === 403);
const ac = await call(ana, "GET", "/api/db-check");
check("MySQL itself denies analyst reading audit_log",
  ac.data.probes.find((p) => p.label === "Read the audit log").allowed === false);
for (const r of ["critical", "fixes", "unpatched", "outdated"]) {
  check(`analyst report ${r}`, (await call(ana, "GET", `/api/analyst/reports?name=${r}`)).status === 200);
}

// ---- admin ----
const reg = await call(adm, "POST", "/api/admin/vulnerabilities", {
  cve_id: "CVE-2024-88888", cvss: 9.1, published: "2024-06-01", version_id: 3, description: "smoke test",
});
check("admin registers CVE, trigger sets CRITICAL", reg.status === 201 && reg.data.vuln.severity === "CRITICAL",
  `opened for: ${reg.data?.opened?.map((o) => o.project).join(", ")}`);
const dup = await call(adm, "POST", "/api/admin/vulnerabilities", {
  cve_id: "CVE-2024-88888", cvss: 9.1, published: "2024-06-01", version_id: 3,
});
check("duplicate CVE is rejected", dup.status === 400, dup.data?.error);
const bad = await call(adm, "POST", "/api/admin/vulnerabilities", { cve_id: "BAD-1", cvss: 5, published: "2024-06-01", version_id: 3 });
check("bad CVE format rejected by CHECK constraint", bad.status === 400, bad.data?.error);
const audit = await call(adm, "GET", "/api/admin/audit");
check("audit log records the analyst's email", audit.data.some((a) => a.changed_by === "meera@example.com"));
check("admin deletes CVE", (await call(adm, "DELETE", "/api/admin/vulnerabilities?cve=CVE-2024-88888")).status === 200);

// ---- MongoDB (needs mongod + migration script) ----
const mg = await call(ana, "GET", "/api/nosql/exposure?cve=CVE-2022-24999");
if (mg.status === 503) {
  console.log("SKIP  MongoDB checks (MongoDB not running)");
} else {
  check("Mongo $graphLookup finds WebShop at depth 3", mg.data.hits?.[0]?._id === "WebShop" && mg.data.hits[0].exposure_depth === 3);
  const n = await call(ana, "POST", "/api/nosql/notes", { cve_id: "CVE-2022-24999", text: "smoke note", tags: ["test"] });
  check("Mongo note created", n.status === 201);
  check("Mongo note read", (await call(ana, "GET", "/api/nosql/notes?cve=CVE-2022-24999")).data.some((x) => x._id === n.data._id));
  check("Mongo note updated", (await call(ana, "PATCH", "/api/nosql/notes", { id: n.data._id, text: "edited" })).status === 200);
  check("Mongo note deleted", (await call(ana, "DELETE", `/api/nosql/notes?id=${n.data._id}`)).status === 200);
  check("developer blocked from Mongo API", (await call(dev, "GET", "/api/nosql/notes")).status === 403);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
