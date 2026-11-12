USE supply_chain_db;
SET SESSION cte_max_recursion_depth = 100;

-- R1: Full transitive dependency chain with readable paths
WITH RECURSIVE chain AS (
  SELECT pd.project_id, pd.version_id, 1 AS depth,
         CAST(CONCAT(',', pd.version_id, ',') AS CHAR(500)) AS id_path,
         CAST(CONCAT(pk.name,'@',pv.version_no) AS CHAR(1000)) AS name_path
  FROM project_dependency pd
  JOIN package_version pv ON pv.version_id = pd.version_id
  JOIN package pk         ON pk.package_id = pv.package_id
  UNION ALL
  SELECT c.project_id, d.child_version_id, c.depth + 1,
         CONCAT(c.id_path, d.child_version_id, ','),
         CONCAT(c.name_path, ' -> ', pk.name, '@', pv.version_no)
  FROM chain c
  JOIN package_dependency d ON d.parent_version_id = c.version_id
  JOIN package_version pv   ON pv.version_id = d.child_version_id
  JOIN package pk           ON pk.package_id = pv.package_id
  WHERE LOCATE(CONCAT(',', d.child_version_id, ','), c.id_path) = 0   -- cycle protection
)
SELECT p.name AS project, c.depth, c.name_path
FROM chain c JOIN project p ON p.project_id = c.project_id
ORDER BY p.name, c.depth;

-- R2: Everything exposed to ONE vulnerability, with the path that introduces it
WITH RECURSIVE chain AS (
  SELECT pd.project_id, pd.version_id, 1 AS depth,
         CAST(CONCAT(',', pd.version_id, ',') AS CHAR(500)) AS id_path,
         CAST(CONCAT(pk.name,'@',pv.version_no) AS CHAR(1000)) AS name_path
  FROM project_dependency pd
  JOIN package_version pv ON pv.version_id = pd.version_id
  JOIN package pk         ON pk.package_id = pv.package_id
  UNION ALL
  SELECT c.project_id, d.child_version_id, c.depth + 1,
         CONCAT(c.id_path, d.child_version_id, ','),
         CONCAT(c.name_path, ' -> ', pk.name, '@', pv.version_no)
  FROM chain c
  JOIN package_dependency d ON d.parent_version_id = c.version_id
  JOIN package_version pv   ON pv.version_id = d.child_version_id
  JOIN package pk           ON pk.package_id = pv.package_id
  WHERE LOCATE(CONCAT(',', d.child_version_id, ','), c.id_path) = 0
)
SELECT p.name AS project, v.cve_id, c.depth, c.name_path
FROM chain c
JOIN vulnerability_affected va ON va.version_id = c.version_id
JOIN vulnerability v           ON v.vuln_id = va.vuln_id
JOIN project p                 ON p.project_id = c.project_id
WHERE v.cve_id = 'CVE-2022-24999';

-- R3: Reverse direction - which versions depend (directly or not) on a given version?
WITH RECURSIVE up AS (
  SELECT version_id FROM package_version WHERE version_id = 5      -- qs 6.5.2
  UNION
  SELECT d.parent_version_id FROM package_dependency d JOIN up ON d.child_version_id = up.version_id
)
SELECT pk.name, pv.version_no
FROM up JOIN package_version pv ON pv.version_id = up.version_id
        JOIN package pk ON pk.package_id = pv.package_id;

-- R4: Detect dependency cycles (expect lib-a and lib-b)
WITH RECURSIVE walk AS (
  SELECT parent_version_id AS start_id, child_version_id AS cur, 1 AS depth,
         CAST(CONCAT(',', parent_version_id, ',', child_version_id, ',') AS CHAR(500)) AS path
  FROM package_dependency
  UNION ALL
  SELECT w.start_id, d.child_version_id, w.depth + 1,
         CONCAT(w.path, d.child_version_id, ',')
  FROM walk w
  JOIN package_dependency d ON d.parent_version_id = w.cur
  WHERE w.cur <> w.start_id
    AND (LOCATE(CONCAT(',', d.child_version_id, ','), w.path) = 0
         OR d.child_version_id = w.start_id)
)
SELECT DISTINCT w.start_id, CONCAT(pk.name,'@',pv.version_no) AS in_cycle, w.path
FROM walk w
JOIN package_version pv ON pv.version_id = w.start_id
JOIN package pk         ON pk.package_id = pv.package_id
WHERE w.cur = w.start_id;