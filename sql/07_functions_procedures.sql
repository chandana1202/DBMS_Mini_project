USE supply_chain_db;
DROP FUNCTION  IF EXISTS calculate_risk_score;
DROP PROCEDURE IF EXISTS get_affected_projects;
DROP PROCEDURE IF EXISTS register_vulnerability;
DROP PROCEDURE IF EXISTS apply_patch;

DELIMITER //

CREATE FUNCTION calculate_risk_score(p_project INT) RETURNS DECIMAL(8,2)
READS SQL DATA
BEGIN
  DECLARE v_score DECIMAL(8,2);
  SELECT COALESCE(SUM(CASE severity WHEN 'CRITICAL' THEN 10 WHEN 'HIGH' THEN 5
                                    WHEN 'MEDIUM' THEN 2 ELSE 1 END), 0)
    INTO v_score
  FROM (SELECT DISTINCT vuln_id, severity
        FROM v_vulnerable_projects WHERE project_id = p_project) t;
  RETURN v_score;
END //

CREATE PROCEDURE get_affected_projects(IN p_cve VARCHAR(20))
BEGIN
  SELECT project, exposure, depth, vulnerable_package, vulnerable_version, dependency_path
  FROM v_vulnerable_projects
  WHERE cve_id = p_cve
  ORDER BY depth, project;
END //

-- Registers a CVE and the affected version in ONE transaction.
-- The triggers from file 08 set the severity and create remediation rows.
CREATE PROCEDURE register_vulnerability(
  IN p_cve VARCHAR(20), IN p_desc TEXT, IN p_cvss DECIMAL(3,1),
  IN p_published DATE,  IN p_affected_version INT)
BEGIN
  DECLARE v_id INT;
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;
    INSERT INTO vulnerability (cve_id, description, cvss_score, published_date)
    VALUES (p_cve, p_desc, p_cvss, p_published);
    SET v_id = LAST_INSERT_ID();
    INSERT INTO vulnerability_affected (vuln_id, version_id) VALUES (v_id, p_affected_version);
  COMMIT;

  SELECT v_id AS new_vuln_id;
END //

-- Upgrades a DIRECT dependency to a registered patch version and closes
-- every remediation the project is no longer exposed to.
CREATE PROCEDURE apply_patch(
  IN p_project INT, IN p_vuln INT, IN p_old_ver INT, IN p_new_ver INT)
BEGIN
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;

  IF NOT EXISTS (SELECT 1 FROM patch WHERE vuln_id = p_vuln AND fixed_version_id = p_new_ver) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'No registered patch for this vulnerability and version';
  END IF;

  UPDATE project_dependency SET version_id = p_new_ver
  WHERE project_id = p_project AND version_id = p_old_ver;

  IF ROW_COUNT() = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Project does not directly depend on the old version';
  END IF;

  UPDATE remediation r
  SET r.status = 'RESOLVED', r.resolved_at = NOW()
  WHERE r.project_id = p_project
    AND r.status <> 'RESOLVED'
    AND NOT EXISTS (SELECT 1 FROM v_vulnerable_projects v
                    WHERE v.project_id = r.project_id AND v.vuln_id = r.vuln_id);

  COMMIT;
END //

DELIMITER ;