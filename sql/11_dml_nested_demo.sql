USE supply_chain_db;

-- ===== NESTED subqueries (3 levels): projects that directly use a version
-- affected by a CRITICAL or HIGH CVE. Expect WebShop, AdminPortal.
SELECT name FROM project WHERE project_id IN (
  SELECT project_id FROM project_dependency WHERE version_id IN (
    SELECT version_id FROM vulnerability_affected WHERE vuln_id IN (
      SELECT vuln_id FROM vulnerability WHERE severity IN ('CRITICAL','HIGH'))));

-- ===== CORRELATED subquery with EXISTS: projects with unresolved remediation
SELECT p.name FROM project p
WHERE EXISTS (SELECT 1 FROM remediation r
              WHERE r.project_id = p.project_id
                AND r.status IN ('OPEN','IN_PROGRESS'));

-- ===== CORRELATED scalar subquery: open items per project
SELECT p.name,
       (SELECT COUNT(*) FROM remediation r
        WHERE r.project_id = p.project_id AND r.status <> 'RESOLVED') AS open_items
FROM project p ORDER BY open_items DESC;

-- ===== DML: INSERT
INSERT INTO package (name, ecosystem, maintainer) VALUES ('moment','npm','moment');
SET @pid = LAST_INSERT_ID();
INSERT INTO package_version (package_id, version_no, release_date)
VALUES (@pid, '2.29.0', '2020-09-22');
SELECT pk.name, pv.version_no FROM package pk
JOIN package_version pv USING (package_id) WHERE pk.package_id = @pid;

-- ===== DML: UPDATE (fires the audit trigger)
UPDATE remediation SET status = 'IN_PROGRESS', assigned_to = 3 WHERE remediation_id = 1;
SELECT table_name, operation, old_data, new_data, changed_by
FROM audit_log ORDER BY log_id DESC LIMIT 1;

-- put the row back
UPDATE remediation SET status = 'OPEN', assigned_to = NULL WHERE remediation_id = 1;

-- ===== DML: DELETE (ON DELETE CASCADE removes the version too)
DELETE FROM package WHERE package_id = @pid;
SELECT COUNT(*) AS versions_left FROM package_version WHERE package_id = @pid;  -- 0