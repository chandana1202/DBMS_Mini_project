\# Requirements



\## Problem statement

Modern applications depend on many third-party packages, which depend on other

packages in turn. A vulnerability in one package can silently affect every

project that uses it, directly or indirectly. This system stores projects,

packages, versions, dependency relationships, vulnerabilities, patches and

remediation status, and traces how a vulnerability propagates to projects.



\## Objectives

\- Store projects, packages, versions and their direct and indirect dependencies

\- Record CVEs with severity, CVSS score, affected versions and available fixes

\- Identify every project exposed to a vulnerability and the path that introduces it

\- Prioritize vulnerabilities and track remediation until resolved

\- Keep an audit history of changes

\- Implement the system in both a relational (MySQL) and a NoSQL (MongoDB) database

\- Provide a UI for exploring the data



\## Functional requirements

1\. Register projects, packages, package versions and users.

2\. Record direct dependencies of projects and dependencies between package versions.

3\. Register vulnerabilities and the package versions they affect.

4\. Derive severity automatically from the CVSS score.

5\. Record patches (fixed versions) for vulnerabilities.

6\. Create remediation records automatically for every exposed project.

7\. Track remediation status (OPEN, IN\_PROGRESS, RESOLVED, IGNORED).

8\. Apply a patch by upgrading a dependency and closing the related remediation.

9\. Log every change to key tables in an audit log.

10\. Restrict access by role (admin, analyst, developer).



\## Questions the database must answer

1\. Which projects are affected by CVE-X, directly or indirectly?

2\. Through which dependency path does the vulnerability reach each project?

3\. Which CRITICAL or HIGH vulnerabilities are still unresolved?

4\. Which packages used by projects are outdated?

5\. Which vulnerabilities have no patch available?

6\. Which fix version should each project upgrade to?

7\. Which projects carry the highest total risk?

8\. Who changed a vulnerability or remediation record, and when?

9\. How many open issues does each project have per severity?

10\. What is the remediation status per project and per assignee?



\## Non-functional requirements

\- \*\*Integrity:\*\* foreign keys, unique keys, NOT NULL and CHECK constraints

\- \*\*Consistency:\*\* multi-step changes run inside transactions

\- \*\*Safety:\*\* circular dependencies must not cause infinite recursion

\- \*\*Auditability:\*\* old and new values are stored for every change

\- \*\*Security:\*\* least-privilege roles; developers see only their own projects



\## DBMS concepts demonstrated

Relational modeling, normalization (3NF), joins, subqueries, aggregation,

window functions, recursive CTEs, views, triggers, stored procedures and

functions, transactions and savepoints, row locking, roles and privileges,

audit logs, and a NoSQL document model with `$graphLookup`.



## Technology

| Layer | Choice | Why it fits this problem |
|---|---|---|
| Relational DB | MySQL 8.0.16+ | Vulnerability data must be consistent: foreign keys, CHECK constraints, triggers and transactions keep remediation and audit data correct. `WITH RECURSIVE` traces dependency chains. GRANTs give real role-based access inside the database. |
| NoSQL DB | MongoDB | A dependency graph is read far more than it is written. Embedding `depends_on` arrays and using `$graphLookup` makes tree reads short. Analyst notes have no fixed shape (tags only on some), which suits a document store. |
| Web app | Next.js 16 (React 19) | One codebase for pages and the API (route handlers), server-side database access so credentials never reach the browser, and a built-in proxy for route guards. |
| Auth | bcryptjs + jose (JWT in an httpOnly cookie) | Passwords stored only as hashes; the cookie cannot be read by page scripts. |
| Styling | Tailwind CSS 4 | Fast, consistent UI without a separate CSS codebase. |
