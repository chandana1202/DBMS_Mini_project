USE supply_chain_db;

-- =====================================================================
-- 10_roles_security.sql  |  Role-based access control INSIDE the database
--   admin_role     : everything
--   analyst_role   : read all business tables/views, update remediation,
--                    run the analysis procedures. NO access to app_user
--                    (password hashes) or audit_log.
--   developer_role : only "my" data, through a filtered view and
--                    ownership-checking procedures (file 12)
-- =====================================================================

-- Developers see only remediation rows of projects THEY own.
-- USER() is the connected account (e.g. asha@localhost); the email prefix maps it to app_user.
CREATE OR REPLACE VIEW v_my_remediation AS
SELECT r.remediation_id, p.name AS project, v.cve_id, v.severity, r.status, r.due_date
FROM remediation r
JOIN project p       ON p.project_id = r.project_id
JOIN vulnerability v ON v.vuln_id = r.vuln_id
JOIN app_user u      ON u.user_id = p.owner_id
WHERE SUBSTRING_INDEX(u.email, '@', 1) = SUBSTRING_INDEX(USER(), '@', 1);

DROP ROLE IF EXISTS 'admin_role', 'analyst_role', 'developer_role';
CREATE ROLE 'admin_role', 'analyst_role', 'developer_role';

-- ----- ADMIN -----
GRANT ALL PRIVILEGES ON supply_chain_db.* TO 'admin_role';

-- ----- SECURITY ANALYST (table-level grants, so audit_log/app_user stay hidden) -----
GRANT SELECT ON supply_chain_db.project                TO 'analyst_role';
GRANT SELECT ON supply_chain_db.package                TO 'analyst_role';
GRANT SELECT ON supply_chain_db.package_version        TO 'analyst_role';
GRANT SELECT ON supply_chain_db.project_dependency     TO 'analyst_role';
GRANT SELECT ON supply_chain_db.package_dependency     TO 'analyst_role';
GRANT SELECT ON supply_chain_db.vulnerability          TO 'analyst_role';
GRANT SELECT ON supply_chain_db.vulnerability_affected TO 'analyst_role';
GRANT SELECT ON supply_chain_db.patch                  TO 'analyst_role';
GRANT SELECT, UPDATE ON supply_chain_db.remediation    TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_dependency_chain          TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_vulnerable_projects       TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_critical_open_issues      TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_outdated_packages         TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_unpatched_vulnerabilities TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_fix_recommendations       TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_project_risk_summary      TO 'analyst_role';
GRANT SELECT ON supply_chain_db.v_remediation_board         TO 'analyst_role';
GRANT EXECUTE ON PROCEDURE supply_chain_db.get_affected_projects  TO 'analyst_role';
GRANT EXECUTE ON PROCEDURE supply_chain_db.apply_patch            TO 'analyst_role';
GRANT EXECUTE ON FUNCTION  supply_chain_db.calculate_risk_score   TO 'analyst_role';

-- ----- DEVELOPER -----
GRANT SELECT ON supply_chain_db.v_my_remediation       TO 'developer_role';
GRANT SELECT ON supply_chain_db.v_project_risk_summary TO 'developer_role';

-- ----- Personal MySQL accounts (for the Workbench demo of v_my_remediation) -----
DROP USER IF EXISTS 'asha'@'localhost', 'meera'@'localhost';
CREATE USER 'asha'@'localhost'  IDENTIFIED BY 'Dev#Pass123';
CREATE USER 'meera'@'localhost' IDENTIFIED BY 'Sec#Pass123';
GRANT 'developer_role' TO 'asha'@'localhost';
GRANT 'analyst_role'   TO 'meera'@'localhost';
SET DEFAULT ROLE ALL TO 'asha'@'localhost', 'meera'@'localhost';
