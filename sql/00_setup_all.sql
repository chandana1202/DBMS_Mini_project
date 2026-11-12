-- =====================================================================
-- 00_setup_all.sql  |  Builds the whole MySQL side in the right order.
-- Run from the PROJECT ROOT folder:
--     mysql -u root -p < sql/00_setup_all.sql
-- or inside the mysql> client:  SOURCE sql/00_setup_all.sql;
-- =====================================================================
SOURCE sql/01_schema.sql;
SOURCE sql/02_constraints_indexes.sql;
SOURCE sql/03_seed_data.sql;
SOURCE sql/06_views.sql;
SOURCE sql/07_functions_procedures.sql;
SOURCE sql/08_triggers_audit.sql;
SOURCE sql/10_roles_security.sql;
SOURCE sql/12_auth_setup.sql;
SOURCE sql/13_auth_login.sql;
-- Demo files (run separately, they print results or change data):
--   04_queries_basic.sql, 05_recursive_queries.sql, 11_dml_nested_demo.sql,
--   09_transactions_demo.sql (changes data), tests/test_cases.sql
