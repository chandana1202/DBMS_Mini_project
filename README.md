# Software Supply-Chain Vulnerability Management Database

UE23CS351A DBMS Project, PES University (Aug–Dec 2026)
Team: **Bhumika Patil** (PES1UG24AM352) and **Chandana O N** (PES1UG24AM353)

A database system that tracks projects, packages, versions, dependencies, CVEs,
patches and remediation status, and traces how a vulnerability in one package
reaches other projects through direct and indirect dependencies.

* **MySQL 8** is the system of record (11 tables in 3NF, views, procedures, triggers, roles).
* **MongoDB** holds a denormalised copy for graph-style reads (`$graphLookup`) and the
  free-form analyst notes.
* **Next.js 16** web app with login and three roles (Admin, Security analyst, Developer).

## Features

* 11 normalized tables with PK/FK, UNIQUE, NOT NULL, ENUM and CHECK constraints
* Recursive CTEs for transitive dependency analysis, with cycle protection
* Views: vulnerable projects, critical open issues, outdated packages, unpatched CVEs,
  fix recommendations, project risk summary, remediation board
* Triggers: severity from CVSS, audit logging, validation, automatic remediation creation
* Stored procedures and a function: `get_affected_projects`, `register_vulnerability`,
  `apply_patch`, `calculate_risk_score`, plus developer procedures `get_my_*`, `update_my_remediation`
* Transactions, savepoints and row-locking demo
* Role-based access control **inside MySQL**: one service account per app role, table-level GRANTs
* MongoDB: `$jsonSchema` validation, `$graphLookup`, `$lookup`, aggregation, full CRUD on notes
* Web app: bcrypt + JWT login, role-based pages and API routes, proxy route guard

## Tech stack

MySQL 8.0.16+, MongoDB 6+, Node.js 20.6+, Next.js 16 (React 19, Tailwind 4), mysql2,
mongodb driver, bcryptjs, jose. Python 3 (pymongo, mysql-connector-python) for the migration script.

## Project structure

```
ER_Diagram.png, Relational_schema.png   design diagrams
docs/        requirements, normalization, SQL vs NoSQL, diagrams (+ generator scripts),
             results (query outputs), screenshots
sql/         00_setup_all.sql runs 01..13 in order
nosql/       migrate_mysql_to_mongo.py, queries.js
tests/       test_cases.sql (SQL features), test_rbac.sh (database permissions)
webapp/      Next.js app (see webapp/README.md)
```

## Setup

### 1. MySQL
From the project root folder:
```
mysql -u root -p < sql/00_setup_all.sql
```
This drops and rebuilds `supply_chain_db`, then creates views, procedures, triggers,
roles and the web app's service accounts. Demo files to run afterwards:
`sql/04_queries_basic.sql`, `sql/05_recursive_queries.sql`, `sql/11_dml_nested_demo.sql`,
`sql/09_transactions_demo.sql` (changes data), `tests/test_cases.sql`.

### 2. MongoDB
```
pip install -r requirements.txt
set DB_PASS=<your mysql root password>        (Windows)
python nosql/migrate_mysql_to_mongo.py
mongosh nosql/queries.js
```

### 3. Web app
```
cd webapp
npm install
copy .env.example .env.local
npm run seed:passwords
npm run dev
```
Open http://localhost:3000. Every demo user's password is `Demo@1234`:

| Email | Role | Can do |
|---|---|---|
| admin@example.com | Admin | Everything, register/delete CVEs, users, audit log |
| meera@example.com | Security analyst | All CVEs, remediation board, reports, MongoDB notes |
| asha@example.com | Developer | Only her projects (WebShop, PaymentService, BlogEngine) |
| ravi@example.com | Developer | Only his projects (AdminPortal, DataPipeline, InternalTools) |

### 4. Tests
```
mysql -u root -p -t --force < tests/test_cases.sql     # 9 SQL feature tests
bash tests/test_rbac.sh                                 # 15 permission tests (Git Bash on Windows)
cd webapp && npm run test:api                           # 30 API tests (app must be running)
```
Saved outputs are in `docs/results/`.

## How authorization works (three layers)

1. **Page guard** – `webapp/proxy.js` redirects logged-out users to `/login` and wrong roles to `/forbidden`.
2. **API guard** – every route calls `guard([...roles])` and returns 401/403.
3. **Database** – the API connects as `app_admin`, `app_analyst` or `app_developer`
   depending on the role. MySQL GRANTs decide what that account may do. For example
   `app_developer` cannot `SELECT` from `vulnerability` at all and works only through
   ownership-checking procedures. The dashboard shows these allowed/denied checks live.

## Example: tracing a vulnerability

`CALL get_affected_projects('CVE-2022-24999');` returns WebShop at depth 3
through `express@4.16.0 -> body-parser@1.18.3 -> qs@6.5.2`.

## Known limitations

* MongoDB's `$graphLookup` returns depth but not the full path; MySQL does.
* MongoDB multi-document transactions need a replica set (`queries.js` N8 explains).
* MySQL has no row-level security; procedures and a filtered view are used instead.
* Seed data is simplified. Verify CVE details against nvd.nist.gov before relying on them.

## Team and contributions

| Area | Bhumika Patil (PES1UG24AM352) | Chandana O N (PES1UG24AM353) |
|---|---|---|
| Design and docs | `requirements.md`, README | ER diagram, relational schema, `normalization.md` |
| Schema and data | `01_schema.sql`, `02_constraints_indexes.sql`, `03_seed_data.sql` | Seed data review, `sql_vs_nosql.md` |
| Queries and views | `04_queries_basic.sql`, `06_views.sql` | `05_recursive_queries.sql`, `11_dml_nested_demo.sql` |
| Programmability and security | `07_functions_procedures.sql`, `09_transactions_demo.sql`, `12_auth_setup.sql`, `13_auth_login.sql` | `08_triggers_audit.sql`, `10_roles_security.sql` |
| NoSQL | `migrate_mysql_to_mongo.py` | `nosql/queries.js` |
| Web app | Login, auth, `lib/`, `proxy.js`, developer and admin pages | Analyst and dependency-graph pages, API routes for them |
| Testing | `webapp/tests/api-smoke.mjs` | `tests/test_cases.sql`, `tests/test_rbac.sh` |
