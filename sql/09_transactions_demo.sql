USE supply_chain_db;

-- Demo 1: SAVEPOINT and partial rollback
START TRANSACTION;
  UPDATE remediation SET status = 'IN_PROGRESS', assigned_to = 3 WHERE remediation_id = 1;
  SAVEPOINT after_first;
  UPDATE remediation SET status = 'IGNORED' WHERE remediation_id = 2;
  SELECT remediation_id, status FROM remediation WHERE remediation_id IN (1,2);
  ROLLBACK TO SAVEPOINT after_first;      -- undoes only the second update
  SELECT remediation_id, status FROM remediation WHERE remediation_id IN (1,2);
COMMIT;

-- Demo 2: a failing procedure rolls back completely (no patch exists for version 999)
CALL apply_patch(2, 4, 9, 999);           -- expect error: No registered patch...
SELECT * FROM project_dependency WHERE project_id = 2;   -- unchanged

-- Demo 3: successful patch (AdminPortal: axios 0.21.0 -> 1.6.0)
CALL apply_patch(2, 4, 9, 10);
SELECT * FROM project_dependency WHERE project_id = 2;
SELECT project_id, vuln_id, status FROM remediation WHERE project_id = 2;
SELECT * FROM audit_log WHERE table_name = 'project_dependency';

-- Demo 4: row locking. Open TWO query tabs in Workbench.
-- Tab 1:
--   START TRANSACTION;
--   SELECT * FROM remediation WHERE remediation_id = 3 FOR UPDATE;
-- Tab 2 (will WAIT until Tab 1 commits or rolls back):
--   UPDATE remediation SET status='IN_PROGRESS' WHERE remediation_id = 3;
-- Tab 1:
--   COMMIT;      -- Tab 2 now completes