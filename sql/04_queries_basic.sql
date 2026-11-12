USE supply_chain_db;

-- Q1: JOIN - direct dependencies that are vulnerable
SELECT p.name AS project, pk.name AS package, pv.version_no, v.cve_id, v.severity
FROM project p
JOIN project_dependency pd      ON pd.project_id = p.project_id
JOIN package_version pv         ON pv.version_id = pd.version_id
JOIN package pk                 ON pk.package_id = pv.package_id
JOIN vulnerability_affected va  ON va.version_id = pv.version_id
JOIN vulnerability v            ON v.vuln_id = va.vuln_id
ORDER BY v.cvss_score DESC;

-- Q2: GROUP BY + HAVING - severities that have more than one CVE
SELECT severity, COUNT(*) AS cve_count, ROUND(AVG(cvss_score),2) AS avg_cvss
FROM vulnerability
GROUP BY severity
HAVING COUNT(*) > 1;

-- Q3: Subquery - package versions older than the latest release of the same package
SELECT pk.name, pv.version_no, pv.release_date
FROM package_version pv
JOIN package pk ON pk.package_id = pv.package_id
WHERE pv.release_date < (SELECT MAX(x.release_date)
                         FROM package_version x
                         WHERE x.package_id = pv.package_id);

-- Q4: Anti-join - vulnerabilities with no patch (expect only CVE-2023-25577)
SELECT v.cve_id, v.severity, v.description
FROM vulnerability v
LEFT JOIN patch pt ON pt.vuln_id = v.vuln_id
WHERE pt.patch_id IS NULL;

-- Q5: Window function - rank CVEs by score within each severity
SELECT cve_id, severity, cvss_score,
       RANK() OVER (PARTITION BY severity ORDER BY cvss_score DESC) AS rank_in_severity
FROM vulnerability;

-- Q6: Fix recommendation for direct dependencies
SELECT p.name AS project, v.cve_id,
       CONCAT(pk.name,'@',pv.version_no) AS current_version,
       CONCAT(fk.name,'@',fv.version_no) AS upgrade_to
FROM project_dependency pd
JOIN project p                 ON p.project_id = pd.project_id
JOIN package_version pv        ON pv.version_id = pd.version_id
JOIN package pk                ON pk.package_id = pv.package_id
JOIN vulnerability_affected va ON va.version_id = pv.version_id
JOIN vulnerability v           ON v.vuln_id = va.vuln_id
JOIN patch pt                  ON pt.vuln_id = v.vuln_id
JOIN package_version fv        ON fv.version_id = pt.fixed_version_id
JOIN package fk                ON fk.package_id = fv.package_id;