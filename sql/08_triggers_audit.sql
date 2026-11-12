USE supply_chain_db;
DELIMITER //

-- ===== Auto-severity from CVSS =====
CREATE TRIGGER trg_vuln_severity_ins BEFORE INSERT ON vulnerability
FOR EACH ROW
BEGIN
  SET NEW.severity = CASE WHEN NEW.cvss_score >= 9 THEN 'CRITICAL'
                          WHEN NEW.cvss_score >= 7 THEN 'HIGH'
                          WHEN NEW.cvss_score >= 4 THEN 'MEDIUM'
                          ELSE 'LOW' END;
END //

CREATE TRIGGER trg_vuln_severity_upd BEFORE UPDATE ON vulnerability
FOR EACH ROW
BEGIN
  SET NEW.severity = CASE WHEN NEW.cvss_score >= 9 THEN 'CRITICAL'
                          WHEN NEW.cvss_score >= 7 THEN 'HIGH'
                          WHEN NEW.cvss_score >= 4 THEN 'MEDIUM'
                          ELSE 'LOW' END;
END //

-- ===== Validation =====
CREATE TRIGGER trg_remediation_validate BEFORE UPDATE ON remediation
FOR EACH ROW
BEGIN
  IF NEW.status = 'RESOLVED' AND NEW.resolved_at IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'resolved_at is required when status is RESOLVED';
  END IF;
END //

CREATE TRIGGER trg_patch_validate BEFORE INSERT ON patch
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM vulnerability_affected
             WHERE vuln_id = NEW.vuln_id AND version_id = NEW.fixed_version_id) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Fixed version is itself affected by this vulnerability';
  END IF;
END //

-- ===== Auto-create remediation for every exposed project (direct or indirect) =====
CREATE TRIGGER trg_affected_create_remediation AFTER INSERT ON vulnerability_affected
FOR EACH ROW
BEGIN
  INSERT IGNORE INTO remediation (project_id, vuln_id, status)
  WITH RECURSIVE up AS (
    SELECT NEW.version_id AS version_id
    UNION
    SELECT d.parent_version_id FROM package_dependency d JOIN up ON d.child_version_id = up.version_id
  )
  SELECT DISTINCT pd.project_id, NEW.vuln_id, 'OPEN'
  FROM project_dependency pd JOIN up ON pd.version_id = up.version_id;
END //

-- ===== Audit: vulnerability =====
CREATE TRIGGER trg_vuln_audit_ins AFTER INSERT ON vulnerability
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, new_data, changed_by)
  VALUES ('vulnerability','INSERT',NEW.vuln_id,
          JSON_OBJECT('cve_id',NEW.cve_id,'cvss',NEW.cvss_score,'severity',NEW.severity), COALESCE(@app_user, USER())) //

CREATE TRIGGER trg_vuln_audit_upd AFTER UPDATE ON vulnerability
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, old_data, new_data, changed_by)
  VALUES ('vulnerability','UPDATE',NEW.vuln_id,
          JSON_OBJECT('cve_id',OLD.cve_id,'cvss',OLD.cvss_score,'severity',OLD.severity),
          JSON_OBJECT('cve_id',NEW.cve_id,'cvss',NEW.cvss_score,'severity',NEW.severity), COALESCE(@app_user, USER())) //

CREATE TRIGGER trg_vuln_audit_del AFTER DELETE ON vulnerability
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, old_data, changed_by)
  VALUES ('vulnerability','DELETE',OLD.vuln_id,
          JSON_OBJECT('cve_id',OLD.cve_id,'cvss',OLD.cvss_score,'severity',OLD.severity), COALESCE(@app_user, USER())) //

-- ===== Audit: remediation =====
CREATE TRIGGER trg_rem_audit_ins AFTER INSERT ON remediation
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, new_data, changed_by)
  VALUES ('remediation','INSERT',NEW.remediation_id,
          JSON_OBJECT('project_id',NEW.project_id,'vuln_id',NEW.vuln_id,'status',NEW.status), COALESCE(@app_user, USER())) //

CREATE TRIGGER trg_rem_audit_upd AFTER UPDATE ON remediation
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, old_data, new_data, changed_by)
  VALUES ('remediation','UPDATE',NEW.remediation_id,
          JSON_OBJECT('status',OLD.status,'assigned_to',OLD.assigned_to),
          JSON_OBJECT('status',NEW.status,'assigned_to',NEW.assigned_to), COALESCE(@app_user, USER())) //

CREATE TRIGGER trg_rem_audit_del AFTER DELETE ON remediation
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, old_data, changed_by)
  VALUES ('remediation','DELETE',OLD.remediation_id,
          JSON_OBJECT('project_id',OLD.project_id,'vuln_id',OLD.vuln_id,'status',OLD.status), COALESCE(@app_user, USER())) //

-- ===== Audit: project_dependency (records version upgrades) =====
CREATE TRIGGER trg_pd_audit_ins AFTER INSERT ON project_dependency
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, new_data, changed_by)
  VALUES ('project_dependency','INSERT',NEW.project_id,
          JSON_OBJECT('version_id',NEW.version_id), COALESCE(@app_user, USER())) //

CREATE TRIGGER trg_pd_audit_upd AFTER UPDATE ON project_dependency
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, old_data, new_data, changed_by)
  VALUES ('project_dependency','UPDATE',NEW.project_id,
          JSON_OBJECT('version_id',OLD.version_id),
          JSON_OBJECT('version_id',NEW.version_id), COALESCE(@app_user, USER())) //

CREATE TRIGGER trg_pd_audit_del AFTER DELETE ON project_dependency
FOR EACH ROW
  INSERT INTO audit_log (table_name, operation, record_id, old_data, changed_by)
  VALUES ('project_dependency','DELETE',OLD.project_id,
          JSON_OBJECT('version_id',OLD.version_id), COALESCE(@app_user, USER())) //

DELIMITER ;

-- ===== Backfill: the seed data was inserted before the trigger existed =====
INSERT IGNORE INTO remediation (project_id, vuln_id, status)
SELECT DISTINCT project_id, vuln_id, 'OPEN' FROM v_vulnerable_projects;