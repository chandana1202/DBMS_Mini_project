USE supply_chain_db;

-- ===== CHECK constraints =====
ALTER TABLE app_user
  ADD CONSTRAINT chk_user_email CHECK (email LIKE '%_@_%._%');

ALTER TABLE package_version
  ADD CONSTRAINT chk_version_not_empty CHECK (CHAR_LENGTH(version_no) > 0);

ALTER TABLE package_dependency
  ADD CONSTRAINT chk_no_self_dep CHECK (parent_version_id <> child_version_id);

ALTER TABLE vulnerability
  ADD CONSTRAINT chk_cve_format CHECK (cve_id REGEXP '^CVE-[0-9]{4}-[0-9]{4,}$'),
  ADD CONSTRAINT chk_cvss_range CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10);

ALTER TABLE remediation
  ADD CONSTRAINT chk_resolved_has_date
    CHECK (status <> 'RESOLVED' OR resolved_at IS NOT NULL);

-- ===== Indexes =====
-- InnoDB automatically indexes foreign key columns, so only add the rest.
CREATE INDEX idx_vuln_severity    ON vulnerability(severity);
CREATE INDEX idx_vuln_published   ON vulnerability(published_date);
CREATE INDEX idx_rem_status       ON remediation(status);
CREATE INDEX idx_pv_release       ON package_version(release_date);