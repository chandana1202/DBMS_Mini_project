USE supply_chain_db;

-- =====================================================================
-- 13_auth_login.sql  |  Login lookup. The web app's login route connects
-- as app_auth, which can run ONLY this procedure (least privilege).
-- =====================================================================

DELIMITER //
DROP PROCEDURE IF EXISTS auth_lookup //
CREATE PROCEDURE auth_lookup(IN p_email VARCHAR(150))
BEGIN
  SELECT user_id, full_name, email, role, password_hash
  FROM app_user WHERE email = p_email;
END //
DELIMITER ;

DROP USER IF EXISTS 'app_auth'@'localhost';
CREATE USER 'app_auth'@'localhost' IDENTIFIED BY 'AuthSvc#2026';
GRANT EXECUTE ON PROCEDURE supply_chain_db.auth_lookup TO 'app_auth'@'localhost';
