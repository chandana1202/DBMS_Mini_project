USE supply_chain_db;
-- Run on FRESH data (right after sql/00_setup_all.sql). Each test lists what to expect.

-- T1 recursive exposure | EXPECT: WebShop, INDIRECT, depth 3, path express -> body-parser -> qs
CALL get_affected_projects('CVE-2022-24999');

-- T2 cycle safety | EXPECT: query finishes, 2 rows (lib-a, lib-b)
WITH RECURSIVE walk AS (
  SELECT parent_version_id AS start_id, child_version_id AS cur,
         CAST(CONCAT(',', parent_version_id, ',', child_version_id, ',') AS CHAR(500)) AS path
  FROM package_dependency
  UNION ALL
  SELECT w.start_id, d.child_version_id, CONCAT(w.path, d.child_version_id, ',')
  FROM walk w JOIN package_dependency d ON d.parent_version_id = w.cur
  WHERE w.cur <> w.start_id
    AND (LOCATE(CONCAT(',', d.child_version_id, ','), w.path) = 0 OR d.child_version_id = w.start_id)
)
SELECT DISTINCT start_id, path FROM walk WHERE cur = start_id;

-- T3 risk score function | EXPECT: WebShop 10.00 (two HIGH CVEs x 5)
SELECT calculate_risk_score(1) AS webshop_risk;

-- T4 severity trigger | EXPECT: severity becomes CRITICAL, audit row written
UPDATE vulnerability SET cvss_score = 9.8 WHERE cve_id = 'CVE-2022-24999';
SELECT cve_id, cvss_score, severity FROM vulnerability WHERE cve_id = 'CVE-2022-24999';
SELECT operation, new_data FROM audit_log
WHERE table_name = 'vulnerability' ORDER BY log_id DESC LIMIT 1;
UPDATE vulnerability SET cvss_score = 7.5 WHERE cve_id = 'CVE-2022-24999';   -- put it back

-- T5 validation trigger | EXPECT: ERROR 1644 'resolved_at is required...'
UPDATE remediation SET status = 'RESOLVED' WHERE remediation_id = 1;

-- T6 patch validation | EXPECT: ERROR 1644 'Fixed version is itself affected...'
INSERT INTO patch (vuln_id, fixed_version_id) VALUES (1, 13);

-- T7 auto-remediation | EXPECT: new CVE gets severity HIGH and 1 OPEN remediation for WebShop
CALL register_vulnerability('CVE-2024-99999', 'Demo bug in body-parser', 8.0, CURDATE(), 3);
SELECT v.cve_id, v.severity, r.project_id, r.status
FROM vulnerability v JOIN remediation r ON r.vuln_id = v.vuln_id
WHERE v.cve_id = 'CVE-2024-99999';

-- T8 CHECK constraint | EXPECT: ERROR 3819 (chk_cve_format)
INSERT INTO vulnerability (cve_id, cvss_score, published_date) VALUES ('BADID', 5.0, CURDATE());

-- T9 ownership check | EXPECT: ERROR 1644 'Not your project...' (Ravi, user 2, does not own WebShop)
CALL update_my_remediation(2, (SELECT remediation_id FROM remediation WHERE project_id = 1 LIMIT 1), 'IN_PROGRESS');

-- clean up T7 so the demo data stays as seeded
DELETE FROM vulnerability WHERE cve_id = 'CVE-2024-99999';
