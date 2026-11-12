#!/usr/bin/env bash
# Database-level RBAC tests. Run from the project root AFTER sql/00_setup_all.sql.
# Each line logs in as one of the web app's MySQL service accounts and tries
# one statement. "ALLOWED" / "DENIED" is decided by MySQL itself, not the app.
H=localhost; DB=supply_chain_db

try () {   # user pass expected sql
  out=$(mysql -h"$H" -u"$1" -p"$2" "$DB" -e "$4" 2>&1 | grep -v Warning)
  if echo "$out" | grep -q "ERROR"; then got=DENIED; else got=ALLOWED; fi
  if [ "$got" = "$3" ]; then res=PASS; else res=FAIL; fi
  printf '%-5s %-14s expect %-8s got %-8s %s\n' "$res" "$1" "$3" "$got" "$4"
}

try app_developer DevSvc#2026     ALLOWED "SELECT * FROM v_project_risk_summary LIMIT 1"
try app_developer DevSvc#2026     ALLOWED "CALL get_my_remediation(1)"
try app_developer DevSvc#2026     DENIED  "SELECT * FROM vulnerability LIMIT 1"
try app_developer DevSvc#2026     DENIED  "UPDATE remediation SET status='OPEN' WHERE 1=0"
try app_developer DevSvc#2026     DENIED  "SELECT * FROM audit_log LIMIT 1"

try app_analyst   AnalystSvc#2026 ALLOWED "SELECT * FROM vulnerability LIMIT 1"
try app_analyst   AnalystSvc#2026 ALLOWED "UPDATE remediation SET status='OPEN' WHERE 1=0"
try app_analyst   AnalystSvc#2026 ALLOWED "CALL get_affected_projects('CVE-2022-24999')"
try app_analyst   AnalystSvc#2026 DENIED  "SELECT * FROM audit_log LIMIT 1"
try app_analyst   AnalystSvc#2026 DENIED  "SELECT password_hash FROM app_user LIMIT 1"
try app_analyst   AnalystSvc#2026 DENIED  "DELETE FROM vulnerability WHERE 1=0"

try app_admin     AdminSvc#2026   ALLOWED "SELECT * FROM audit_log LIMIT 1"
try app_admin     AdminSvc#2026   ALLOWED "SELECT user_id, email FROM app_user LIMIT 1"

try app_auth      AuthSvc#2026    ALLOWED "CALL auth_lookup('admin@example.com')"
try app_auth      AuthSvc#2026    DENIED  "SELECT * FROM app_user LIMIT 1"
