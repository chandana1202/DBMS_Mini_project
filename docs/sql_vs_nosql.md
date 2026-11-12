\# SQL (MySQL) vs NoSQL (MongoDB) for Supply-Chain Vulnerability Tracking



The same dataset (6 projects, 26 package versions, 7 CVEs) is implemented in

both MySQL (`supply\_chain\_db`) and MongoDB (`supply\_chain\_nosql`).

`nosql/migrate\_mysql\_to\_mongo.py` copies the data from MySQL into MongoDB.



\## 1. Data model



| Aspect | MySQL | MongoDB |

|---|---|---|

| Structure | 11 normalized tables (3NF) | 5 collections |

| Dependencies | `package\_dependency` and `project\_dependency` link tables | `depends\_on` and `direct\_deps` arrays embedded in documents |

| Vulnerability data | `vulnerability`, `vulnerability\_affected`, `patch` | One document with embedded `affected` and `patches` arrays |

| Reads | Multi-table JOINs | Single-document reads |

| Redundancy | Minimal, by design | Deliberate denormalization |



\## 2. Transitive dependency analysis



| | MySQL | MongoDB |

|---|---|---|

| Mechanism | `WITH RECURSIVE` CTE | `$graphLookup` aggregation stage |

| Cycle protection | Manual: path string checked with `LOCATE` | Built in: visited documents are tracked |

| Dependency path output | Yes (`express@4.16.0 -> body-parser@1.18.3 -> qs@6.5.2`) | No: only reachable components and their depth |

| Verbosity | Long query | Short pipeline |



Tracing the exact path that introduces a vulnerability is a core requirement,

and SQL does it more naturally. In MongoDB the path would have to be rebuilt in

application code.



\## 3. Integrity and constraints



\- \*\*MySQL:\*\* primary and foreign keys, UNIQUE, NOT NULL, ENUM, and CHECK

&#x20; constraints (CVE ID format, CVSS range, no self-dependency). The database

&#x20; itself rejects invalid data.

\- \*\*MongoDB:\*\* no foreign keys. A `direct\_deps` entry pointing to a missing

&#x20; component is accepted unless the application or a `$jsonSchema` validator

&#x20; checks it. The migration script adds `$jsonSchema` validators to

&#x20; `vulnerabilities` (CVE format, CVSS range, severity enum) and `analyst_notes`. Only the unique index on `(project, cve\_id)` is enforced.



\## 4. Triggers, procedures and transactions



| Feature | MySQL | MongoDB |

|---|---|---|

| Audit logging | Triggers on every INSERT/UPDATE/DELETE | Written by the application (Change Streams or Atlas Triggers are alternatives) |

| Severity from CVSS | `BEFORE INSERT/UPDATE` trigger | Application code |

| Auto-create remediation | `AFTER INSERT` trigger with recursive CTE | Application code |

| Stored procedures | `apply\_patch`, `register\_vulnerability`, `get\_affected\_projects` | Not supported natively |

| Transactions | `START TRANSACTION`, `SAVEPOINT`, `ROLLBACK` | Multi-document transactions need a replica set |

| Access control | Roles, GRANT, filtered views | Role-based access; no row-level security either |



\## 5. Normalization vs denormalization



MySQL avoids update anomalies by storing each fact once. MongoDB duplicates

some information (for example the `"name@version"` string used as an ID) for

read speed. That is acceptable for a dependency graph that is read far more

often than it is written.



\## 6. Results observed



Both backends return the same exposure results. For example,

CVE-2022-24999 exposes WebShop at depth 3 in both. The Next.js app shows the

MySQL result on the Vulnerabilities page and the MongoDB result on the

Dependency graph page.



\## 7. When to use which



\- \*\*MySQL:\*\* strong integrity, auditing, role-based access, business rules

&#x20; enforced in the database, and path reporting.

\- \*\*MongoDB:\*\* flexible schemas (different ecosystems have different metadata),

&#x20; fast graph-style reads, and simple horizontal scaling.

\- \*\*For this project:\*\* MySQL is the system of record. MongoDB works well as

&#x20; a read-optimized copy for dependency exploration.

