USE supply_chain_db;

-- =====================================================================
-- 12_auth_setup.sql  |  Procedures the web app calls for DEVELOPERS,
-- plus one MySQL service account per application role.
-- (app_user.password_hash is created in 01_schema.sql)
-- =====================================================================

DELIMITER //

DROP PROCEDURE IF EXISTS get_my_remediation //
CREATE PROCEDURE get_my_remediation(IN p_user INT)
BEGIN
  SELECT r.remediation_id, p.name AS project, v.cve_id, v.severity, v.cvss_score,
         r.status, r.due_date, r.resolved_at
  FROM remediation r
  JOIN project p       ON p.project_id = r.project_id
  JOIN vulnerability v ON v.vuln_id = r.vuln_id
  WHERE p.owner_id = p_user
  ORDER BY v.cvss_score DESC;
END //

DROP PROCEDURE IF EXISTS get_my_exposure //
CREATE PROCEDURE get_my_exposure(IN p_user INT)
BEGIN
  SELECT vp.project, vp.cve_id, vp.severity, vp.exposure, vp.depth,
         vp.dependency_path
  FROM v_vulnerable_projects vp
  JOIN project p ON p.project_id = vp.project_id
  WHERE p.owner_id = p_user
  ORDER BY vp.cvss_score DESC;
END //

-- A developer may change status only on remediation rows of projects they own
DROP PROCEDURE IF EXISTS update_my_remediation //
CREATE PROCEDURE update_my_remediation(IN p_user INT, IN p_rem INT, IN p_status VARCHAR(20))
BEGIN
  IF p_status NOT IN ('OPEN','IN_PROGRESS','RESOLVED','IGNORED') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid status';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM remediation r
                 JOIN project p ON p.project_id = r.project_id
                 WHERE r.remediation_id = p_rem AND p.owner_id = p_user) THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'Not your project, or remediation not found';
  END IF;
  UPDATE remediation
  SET status = p_status,
      resolved_at = IF(p_status = 'RESOLVED', NOW(), NULL)
  WHERE remediation_id = p_rem;
END //

DELIMITER ;

-- Roles (file 10 creates them; IF NOT EXISTS keeps this file safe)
CREATE ROLE IF NOT EXISTS 'admin_role', 'analyst_role', 'developer_role';

GRANT EXECUTE ON PROCEDURE supply_chain_db.get_my_remediation    TO 'developer_role';
GRANT EXECUTE ON PROCEDURE supply_chain_db.get_my_exposure       TO 'developer_role';
GRANT EXECUTE ON PROCEDURE supply_chain_db.update_my_remediation TO 'developer_role';

-- Service accounts used by the web app (one per role).
-- The app picks the account from the logged-in user's role, so MySQL itself
-- enforces what each role can do.
DROP USER IF EXISTS 'app_admin'@'localhost', 'app_analyst'@'localhost', 'app_developer'@'localhost';
CREATE USER 'app_admin'@'localhost'     IDENTIFIED BY 'AdminSvc#2026';
CREATE USER 'app_analyst'@'localhost'   IDENTIFIED BY 'AnalystSvc#2026';
CREATE USER 'app_developer'@'localhost' IDENTIFIED BY 'DevSvc#2026';
GRANT 'admin_role'     TO 'app_admin'@'localhost';
GRANT 'analyst_role'   TO 'app_analyst'@'localhost';
GRANT 'developer_role' TO 'app_developer'@'localhost';
SET DEFAULT ROLE ALL TO 'app_admin'@'localhost', 'app_analyst'@'localhost', 'app_developer'@'localhost';
