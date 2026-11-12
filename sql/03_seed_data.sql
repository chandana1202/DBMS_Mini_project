USE supply_chain_db;

-- ========== PART 1: users, projects, packages, versions ==========
INSERT INTO app_user (user_id, full_name, email, role) VALUES
(1,'Asha Nair',   'asha@example.com',  'DEVELOPER'),
(2,'Ravi Kumar',  'ravi@example.com',  'DEVELOPER'),
(3,'Meera Iyer',  'meera@example.com', 'SECURITY_ANALYST'),
(4,'Admin User',  'admin@example.com', 'ADMIN');

INSERT INTO project (project_id, name, owner_id, repo_url, language, criticality) VALUES
(1,'WebShop',        1,'https://github.com/demo/webshop',        'JavaScript','HIGH'),
(2,'AdminPortal',    2,'https://github.com/demo/adminportal',    'JavaScript','MEDIUM'),
(3,'PaymentService', 1,'https://github.com/demo/paymentservice', 'Java',      'CRITICAL'),
(4,'DataPipeline',   2,'https://github.com/demo/datapipeline',   'Python',    'MEDIUM'),
(5,'BlogEngine',     1,'https://github.com/demo/blogengine',     'Python',    'LOW'),
(6,'InternalTools',  2,'https://github.com/demo/internaltools',  'JavaScript','LOW');

INSERT INTO package (package_id, name, ecosystem, maintainer) VALUES
(1,'express',          'npm',  'expressjs'),
(2,'body-parser',      'npm',  'expressjs'),
(3,'qs',               'npm',  'ljharb'),
(4,'lodash',           'npm',  'lodash'),
(5,'axios',            'npm',  'axios'),
(6,'follow-redirects', 'npm',  'follow-redirects'),
(7,'log4j-core',       'Maven','apache'),
(8,'log4j-api',        'Maven','apache'),
(9,'spring-boot',      'Maven','vmware'),
(10,'requests',        'PyPI', 'psf'),
(11,'urllib3',         'PyPI', 'urllib3'),
(12,'flask',           'PyPI', 'pallets'),
(13,'werkzeug',        'PyPI', 'pallets'),
(14,'lib-a',           'npm',  'demo'),
(15,'lib-b',           'npm',  'demo');

INSERT INTO package_version (version_id, package_id, version_no, release_date) VALUES
(1, 1,'4.16.0','2018-09-28'), (2, 1,'4.18.2','2022-10-08'),
(3, 2,'1.18.3','2018-05-14'), (4, 2,'1.20.1','2022-10-06'),
(5, 3,'6.5.2', '2018-05-16'), (6, 3,'6.11.0','2022-09-08'),
(7, 4,'4.17.15','2019-07-19'),(8, 4,'4.17.21','2021-02-20'),
(9, 5,'0.21.0','2020-10-23'), (10,5,'1.6.0', '2023-10-26'),
(11,6,'1.13.0','2020-09-02'), (12,6,'1.15.4','2023-12-29'),
(13,7,'2.14.1','2021-03-06'), (14,7,'2.17.1','2021-12-28'),
(15,8,'2.14.1','2021-03-06'), (16,8,'2.17.1','2021-12-28'),
(17,9,'2.5.0', '2021-05-20'), (18,9,'2.7.0', '2022-05-19'),
(19,10,'2.25.0','2020-11-11'),(20,10,'2.31.0','2023-05-22'),
(21,11,'1.26.4','2021-03-15'),(22,11,'1.26.18','2023-10-17'),
(23,12,'2.0.0', '2021-05-11'),(24,13,'2.0.0', '2021-05-11'),
(25,14,'1.0.0', '2022-01-01'),(26,15,'1.0.0', '2022-01-01');
-- ========== PART 2: dependencies, vulnerabilities, patches ==========

-- Direct dependencies of projects
INSERT INTO project_dependency (project_id, version_id) VALUES
(1,1),(1,7),     -- WebShop       -> express 4.16.0, lodash 4.17.15
(2,9),(2,7),     -- AdminPortal   -> axios 0.21.0, lodash 4.17.15
(3,17),          -- PaymentService-> spring-boot 2.5.0
(4,19),          -- DataPipeline  -> requests 2.25.0
(5,23),          -- BlogEngine    -> flask 2.0.0
(6,25);          -- InternalTools -> lib-a (cycle demo)

-- Package-to-package (transitive) edges
INSERT INTO package_dependency (parent_version_id, child_version_id) VALUES
(1,3),(3,5),     -- express -> body-parser -> qs
(9,11),          -- axios -> follow-redirects
(17,13),(13,15), -- spring-boot -> log4j-core -> log4j-api
(19,21),         -- requests -> urllib3
(23,24),         -- flask -> werkzeug
(25,26),(26,25); -- CYCLE: lib-a <-> lib-b (tests cycle protection)

-- Severity is supplied explicitly here; a trigger will derive it later (commit #16)
INSERT INTO vulnerability (vuln_id, cve_id, description, cvss_score, severity, published_date) VALUES
(1,'CVE-2021-44228','Log4Shell: remote code execution via JNDI lookup in log4j-core',10.0,'CRITICAL','2021-12-10'),
(2,'CVE-2022-24999','qs prototype pollution allowing denial of service',              7.5,'HIGH',    '2022-11-26'),
(3,'CVE-2021-23337','lodash command injection via template function',                 7.2,'HIGH',    '2021-02-15'),
(4,'CVE-2020-28168','axios server-side request forgery via redirects',                 5.9,'MEDIUM',  '2020-11-06'),
(5,'CVE-2023-43804','urllib3 leaks Cookie header on cross-origin redirect',            8.1,'HIGH',    '2023-10-04'),
(6,'CVE-2023-25577','werkzeug multipart parsing denial of service',                    7.5,'HIGH',    '2023-02-14'),
(7,'CVE-2023-26159','follow-redirects improper URL input validation',                  6.1,'MEDIUM',  '2024-01-02');

INSERT INTO vulnerability_affected (vuln_id, version_id) VALUES
(1,13),(2,5),(3,7),(4,9),(5,21),(6,24),(7,11);

-- CVE 6 (werkzeug) intentionally has NO patch -> used for the "unpatched" query
INSERT INTO patch (vuln_id, fixed_version_id, release_date, notes) VALUES
(1,14,'2021-12-28','Upgrade log4j-core to 2.17.1'),
(2,6, '2022-09-08','Upgrade qs to 6.11.0'),
(3,8, '2021-02-20','Upgrade lodash to 4.17.21'),
(4,10,'2023-10-26','Upgrade axios to 1.6.0'),
(5,22,'2023-10-17','Upgrade urllib3 to 1.26.18'),
(7,12,'2023-12-29','Upgrade follow-redirects to 1.15.4');