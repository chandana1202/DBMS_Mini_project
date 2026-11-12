-- 01_schema.sql  |  Requires MySQL 8.0.16+
DROP DATABASE IF EXISTS supply_chain_db;
CREATE DATABASE supply_chain_db CHARACTER SET utf8mb4;
USE supply_chain_db;

-- ========== PART A: core tables ==========

CREATE TABLE app_user (
  user_id    INT AUTO_INCREMENT PRIMARY KEY,
  full_name  VARCHAR(100) NOT NULL,
  email      VARCHAR(150) NOT NULL UNIQUE,
  role       ENUM('DEVELOPER','SECURITY_ANALYST','ADMIN') NOT NULL DEFAULT 'DEVELOPER',
  password_hash VARCHAR(100) NULL,          -- bcrypt hash, filled by webapp/scripts/seed-passwords.mjs
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE project (
  project_id  INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(100) NOT NULL UNIQUE,
  owner_id    INT NOT NULL,
  repo_url    VARCHAR(255),
  language    VARCHAR(30),
  criticality ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_project_owner FOREIGN KEY (owner_id) REFERENCES app_user(user_id)
) ENGINE=InnoDB;

CREATE TABLE package (
  package_id INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(150) NOT NULL,
  ecosystem  ENUM('npm','PyPI','Maven') NOT NULL,
  maintainer VARCHAR(100),
  CONSTRAINT uq_package UNIQUE (name, ecosystem)
) ENGINE=InnoDB;

CREATE TABLE package_version (
  version_id    INT AUTO_INCREMENT PRIMARY KEY,
  package_id    INT NOT NULL,
  version_no    VARCHAR(30) NOT NULL,
  release_date  DATE,
  is_deprecated BOOLEAN NOT NULL DEFAULT FALSE,
  CONSTRAINT uq_pkg_version UNIQUE (package_id, version_no),
  CONSTRAINT fk_pv_package FOREIGN KEY (package_id) REFERENCES package(package_id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

-- A project's DIRECT dependencies
CREATE TABLE project_dependency (
  project_id INT NOT NULL,
  version_id INT NOT NULL,
  added_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (project_id, version_id),
  CONSTRAINT fk_pd_project FOREIGN KEY (project_id) REFERENCES project(project_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_pd_version FOREIGN KEY (version_id) REFERENCES package_version(version_id)
) ENGINE=InnoDB;

-- Package-to-package edges (parent version REQUIRES child version).
-- No ON DELETE CASCADE here: columns used in a CHECK (added in file 02)
-- cannot have cascading referential actions in MySQL.
CREATE TABLE package_dependency (
  parent_version_id INT NOT NULL,
  child_version_id  INT NOT NULL,
  PRIMARY KEY (parent_version_id, child_version_id),
  CONSTRAINT fk_pkgdep_parent FOREIGN KEY (parent_version_id) REFERENCES package_version(version_id),
  CONSTRAINT fk_pkgdep_child  FOREIGN KEY (child_version_id)  REFERENCES package_version(version_id)
) ENGINE=InnoDB;
-- ========== PART B: vulnerability side ==========

CREATE TABLE vulnerability (
  vuln_id        INT AUTO_INCREMENT PRIMARY KEY,
  cve_id         VARCHAR(20) NOT NULL UNIQUE,
  description    TEXT,
  cvss_score     DECIMAL(3,1),
  severity       ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
  published_date DATE NOT NULL
) ENGINE=InnoDB;

-- Which package versions are affected by which vulnerability
CREATE TABLE vulnerability_affected (
  vuln_id    INT NOT NULL,
  version_id INT NOT NULL,
  PRIMARY KEY (vuln_id, version_id),
  CONSTRAINT fk_va_vuln    FOREIGN KEY (vuln_id)    REFERENCES vulnerability(vuln_id) ON DELETE CASCADE,
  CONSTRAINT fk_va_version FOREIGN KEY (version_id) REFERENCES package_version(version_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE patch (
  patch_id         INT AUTO_INCREMENT PRIMARY KEY,
  vuln_id          INT NOT NULL,
  fixed_version_id INT NOT NULL,
  release_date     DATE,
  notes            VARCHAR(255),
  CONSTRAINT uq_patch UNIQUE (vuln_id, fixed_version_id),
  CONSTRAINT fk_patch_vuln    FOREIGN KEY (vuln_id)          REFERENCES vulnerability(vuln_id) ON DELETE CASCADE,
  CONSTRAINT fk_patch_version FOREIGN KEY (fixed_version_id) REFERENCES package_version(version_id)
) ENGINE=InnoDB;

CREATE TABLE remediation (
  remediation_id INT AUTO_INCREMENT PRIMARY KEY,
  project_id     INT NOT NULL,
  vuln_id        INT NOT NULL,
  status         ENUM('OPEN','IN_PROGRESS','RESOLVED','IGNORED') NOT NULL DEFAULT 'OPEN',
  assigned_to    INT NULL,
  due_date       DATE,
  resolved_at    DATETIME NULL,
  CONSTRAINT uq_remediation UNIQUE (project_id, vuln_id),
  CONSTRAINT fk_rem_project  FOREIGN KEY (project_id)  REFERENCES project(project_id) ON DELETE CASCADE,
  CONSTRAINT fk_rem_vuln     FOREIGN KEY (vuln_id)     REFERENCES vulnerability(vuln_id) ON DELETE CASCADE,
  CONSTRAINT fk_rem_assignee FOREIGN KEY (assigned_to) REFERENCES app_user(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE audit_log (
  log_id     BIGINT AUTO_INCREMENT PRIMARY KEY,
  table_name VARCHAR(50)  NOT NULL,
  operation  ENUM('INSERT','UPDATE','DELETE') NOT NULL,
  record_id  INT,
  old_data   JSON,
  new_data   JSON,
  changed_by VARCHAR(100),
  changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;