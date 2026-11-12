\# Normalization



\## 1. Unnormalized data (UNF)

A single sheet containing everything:



| project | owner | owner\_email | package | ecosystem | version | cve\_id | cvss | severity | fixed\_in |

|---|---|---|---|---|---|---|---|---|---|

| WebShop | Asha Nair | asha@example.com | qs | npm | 6.5.2 | CVE-2022-24999 | 7.5 | HIGH | qs 6.11.0 |

| WebShop | Asha Nair | asha@example.com | lodash | npm | 4.17.15 | CVE-2021-23337 | 7.2 | HIGH | lodash 4.17.21 |

| PaymentService | Asha Nair | asha@example.com | log4j-core | Maven | 2.14.1 | CVE-2021-44228 | 10.0 | CRITICAL | log4j-core 2.17.1 |



\### Anomalies

\- \*\*Update:\*\* changing Asha's email means editing every row she appears in.

\- \*\*Insertion:\*\* a new CVE cannot be stored until some project uses an affected package.

\- \*\*Deletion:\*\* deleting the last project that uses a package also deletes the CVE record.

\- \*\*Redundancy:\*\* owner, ecosystem and CVE details repeat on every row.



\## 2. First Normal Form (1NF)

\- Every column holds one atomic value (no lists of packages or CVEs in a cell).

\- Each row is uniquely identified by a key, for example (project, package, version, cve\_id).

\- Multi-valued facts (many packages per project, many CVEs per version) become separate rows.



\## 3. Second Normal Form (2NF)

Remove attributes that depend on only part of the composite key.



| Partial dependency | Moved to |

|---|---|

| project -> owner, language, criticality | `project` |

| package -> ecosystem, maintainer | `package` |

| (package, version) -> release\_date | `package\_version` |

| cve\_id -> description, cvss, severity, published\_date | `vulnerability` |



The many-to-many relationships become link tables:

`project\_dependency`, `vulnerability\_affected`, and `remediation`.



\## 4. Third Normal Form (3NF)

Remove transitive dependencies (non-key attributes that depend on other non-key attributes).



| Transitive dependency | Resolution |

|---|---|

| project -> owner -> owner\_email | `app\_user` table; `project.owner\_id` is a foreign key |

| cvss\_score -> severity | Severity is derived from CVSS. It is kept as a column for query speed and maintained by a trigger, so it cannot drift from the score |

| patch -> fixed version attributes | `patch.fixed\_version\_id` references `package\_version` |



The self-referencing many-to-many relationship between package versions is stored in

`package\_dependency (parent\_version\_id, child\_version\_id)`.



\## 5. Final relations

| Table | Primary key | Foreign keys |

|---|---|---|

| app\_user | user\_id | none |

| project | project\_id | owner\_id -> app\_user |

| package | package\_id | none |

| package\_version | version\_id | package\_id -> package |

| project\_dependency | (project\_id, version\_id) | project, package\_version |

| package\_dependency | (parent\_version\_id, child\_version\_id) | package\_version (twice) |

| vulnerability | vuln\_id | none |

| vulnerability\_affected | (vuln\_id, version\_id) | vulnerability, package\_version |

| patch | patch\_id | vuln\_id -> vulnerability, fixed\_version\_id -> package\_version |

| remediation | remediation\_id | project, vulnerability, app\_user (assignee) |

| audit\_log | log\_id | none by design (it records changes to any table) |



In every table, each non-key attribute depends on the key, the whole key, and

nothing but the key.



\## 6. Deliberate exception

`vulnerability.severity` is derived from `cvss\_score`, which is a transitive

dependency. It is kept because severity is filtered and indexed constantly, and

the `BEFORE INSERT/UPDATE` triggers guarantee it stays consistent.



\## 7. NoSQL

The MongoDB version intentionally denormalizes: dependencies are embedded as

arrays inside component and project documents. See `sql\_vs\_nosql.md`.

