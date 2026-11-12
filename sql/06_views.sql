USE supply_chain_db;

CREATE OR REPLACE VIEW v_dependency_chain AS
WITH RECURSIVE chain AS (
  SELECT pd.project_id, pd.version_id, 1 AS depth,
         CAST(CONCAT(',', pd.version_id, ',') AS CHAR(500)) AS id_path,
         CAST(CONCAT(pk.name,'@',pv.version_no) AS CHAR(1000)) AS name_path
  FROM project_dependency pd
  JOIN package_version pv ON pv.version_id = pd.version_id
  JOIN package pk         ON pk.package_id = pv.package_id
  UNION ALL
  SELECT c.project_id, d.child_version_id, c.depth + 1,
         CONCAT(c.id_path, d.child_version_id, ','),
         CONCAT(c.name_path, ' -> ', pk.name, '@', pv.version_no)
  FROM chain c
  JOIN package_dependency d ON d.parent_version_id = c.version_id
  JOIN package_version pv   ON pv.version_id = d.child_version_id
  JOIN package pk           ON pk.package_id = pv.package_id
  WHERE LOCATE(CONCAT(',', d.child_version_id, ','), c.id_path) = 0
)
SELECT project_id, version_id, depth, id_path, name_path FROM chain;

CREATE OR REPLACE VIEW v_vulnerable_projects AS
SELECT p.project_id, p.name AS project, v.vuln_id, v.cve_id, v.severity, v.cvss_score,
       pk.name AS vulnerable_package, pv.version_no AS vulnerable_version,
       c.depth, IF(c.depth = 1, 'DIRECT', 'INDIRECT') AS exposure,
       c.name_path AS dependency_path
FROM v_dependency_chain c
JOIN vulnerability_affected va ON va.version_id = c.version_id
JOIN vulnerability v           ON v.vuln_id = va.vuln_id
JOIN package_version pv        ON pv.version_id = c.version_id
JOIN package pk                ON pk.package_id = pv.package_id
JOIN project p                 ON p.project_id = c.project_id;

CREATE OR REPLACE VIEW v_critical_open_issues AS
SELECT p.name AS project, v.cve_id, v.severity, v.cvss_score,
       r.status, u.full_name AS assignee, r.due_date
FROM remediation r
JOIN project p            ON p.project_id = r.project_id
JOIN vulnerability v      ON v.vuln_id = r.vuln_id
LEFT JOIN app_user u      ON u.user_id = r.assigned_to
WHERE r.status IN ('OPEN','IN_PROGRESS')
  AND v.severity IN ('CRITICAL','HIGH');

CREATE OR REPLACE VIEW v_outdated_packages AS
SELECT DISTINCT p.name AS project, pk.name AS package,
       pv.version_no AS current_version, latest.version_no AS latest_version
FROM v_dependency_chain c
JOIN project p            ON p.project_id = c.project_id
JOIN package_version pv   ON pv.version_id = c.version_id
JOIN package pk           ON pk.package_id = pv.package_id
JOIN package_version latest ON latest.package_id = pv.package_id
     AND latest.release_date = (SELECT MAX(x.release_date) FROM package_version x
                                WHERE x.package_id = pv.package_id)
WHERE pv.release_date < latest.release_date;

CREATE OR REPLACE VIEW v_unpatched_vulnerabilities AS
SELECT v.cve_id, v.severity, v.cvss_score, v.description
FROM vulnerability v
LEFT JOIN patch pt ON pt.vuln_id = v.vuln_id
WHERE pt.patch_id IS NULL;

CREATE OR REPLACE VIEW v_fix_recommendations AS
SELECT vp.project, vp.cve_id, vp.severity, vp.exposure,
       CONCAT(vp.vulnerable_package,'@',vp.vulnerable_version) AS vulnerable_component,
       CONCAT(fk.name,'@',fv.version_no) AS fixed_in
FROM v_vulnerable_projects vp
LEFT JOIN patch pt          ON pt.vuln_id = vp.vuln_id
LEFT JOIN package_version fv ON fv.version_id = pt.fixed_version_id
LEFT JOIN package fk         ON fk.package_id = fv.package_id;

CREATE OR REPLACE VIEW v_project_risk_summary AS
SELECT t.*, (t.critical_cnt * 10 + t.high_cnt * 5 + t.medium_cnt * 2 + t.low_cnt) AS risk_score
FROM (
  SELECT p.project_id, p.name AS project, p.criticality,
         COUNT(DISTINCT CASE WHEN vp.severity = 'CRITICAL' THEN vp.vuln_id END) AS critical_cnt,
         COUNT(DISTINCT CASE WHEN vp.severity = 'HIGH'     THEN vp.vuln_id END) AS high_cnt,
         COUNT(DISTINCT CASE WHEN vp.severity = 'MEDIUM'   THEN vp.vuln_id END) AS medium_cnt,
         COUNT(DISTINCT CASE WHEN vp.severity = 'LOW'      THEN vp.vuln_id END) AS low_cnt
  FROM project p
  LEFT JOIN v_vulnerable_projects vp ON vp.project_id = p.project_id
  GROUP BY p.project_id, p.name, p.criticality
) t;

-- Remediation board for the web app: every remediation with project, CVE and
-- assignee NAME only (so analysts never need SELECT on app_user).
CREATE OR REPLACE VIEW v_remediation_board AS
SELECT r.remediation_id, r.project_id, p.name AS project, v.cve_id, v.severity, v.cvss_score,
       r.status, r.assigned_to, u.full_name AS assignee, r.due_date, r.resolved_at
FROM remediation r
JOIN project p       ON p.project_id = r.project_id
JOIN vulnerability v ON v.vuln_id = r.vuln_id
LEFT JOIN app_user u ON u.user_id = r.assigned_to;

-- Window function on top of the summary view
SELECT project, risk_score, RANK() OVER (ORDER BY risk_score DESC) AS risk_rank
FROM v_project_risk_summary;