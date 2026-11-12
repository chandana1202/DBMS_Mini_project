"""
Copies the MySQL data (supply_chain_db) into MongoDB (supply_chain_nosql).

    pip install -r requirements.txt
    set DB_PASS=<your mysql root password>        (Windows)
    export DB_PASS=<your mysql root password>     (Mac/Linux)
    python nosql/migrate_mysql_to_mongo.py

Collections created:
  components       one document per package version, with an embedded depends_on array
  projects         one document per project, with an embedded direct_deps array
  vulnerabilities  one document per CVE, with embedded affected[] and patches[]  ($jsonSchema validated)
  remediation      one document per (project, CVE)
  analyst_notes    free-form notes analysts attach to a CVE (CRUD from the web app, $jsonSchema validated)
  audit_log        change history written by the web app
"""
import os
from datetime import datetime, timezone

import mysql.connector
from pymongo import MongoClient

MYSQL = dict(host=os.environ.get("DB_HOST", "localhost"),
             user=os.environ.get("DB_USER", "root"),
             password=os.environ["DB_PASS"],
             database="supply_chain_db")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

my = mysql.connector.connect(**MYSQL)
cur = my.cursor(dictionary=True)
db = MongoClient(MONGO_URI)["supply_chain_nosql"]


def q(sql):
    cur.execute(sql)
    return cur.fetchall()


def clean(v):  # pymongo cannot store date/Decimal
    if hasattr(v, "isoformat"):
        return v.isoformat()
    if v.__class__.__name__ == "Decimal":
        return float(v)
    return v


for c in ["components", "projects", "vulnerabilities", "remediation", "analyst_notes", "audit_log"]:
    db[c].drop()

# ---------- schema validation (MongoDB's answer to CHECK / NOT NULL) ----------
db.create_collection("vulnerabilities", validator={"$jsonSchema": {
    "bsonType": "object",
    "required": ["cve_id", "severity", "published", "affected", "patches"],
    "properties": {
        "cve_id":   {"bsonType": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"},
        "cvss":     {"bsonType": ["double", "int", "null"], "minimum": 0, "maximum": 10},
        "severity": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "affected": {"bsonType": "array", "items": {"bsonType": "string"}},
        "patches":  {"bsonType": "array"},
    }}})

db.create_collection("analyst_notes", validator={"$jsonSchema": {
    "bsonType": "object",
    "required": ["cve_id", "text", "author", "created_at"],
    "properties": {
        "cve_id":     {"bsonType": "string"},
        "text":       {"bsonType": "string", "minLength": 1, "maxLength": 1000},
        "author":     {"bsonType": "string"},
        "tags":       {"bsonType": "array", "items": {"bsonType": "string"}},
        "created_at": {"bsonType": "date"},
        "updated_at": {"bsonType": "date"},
    }}})

# ---------- components: one doc per package version ----------
vid = {}
comps = {}
for r in q("""SELECT pv.version_id, pk.name, pk.ecosystem, pv.version_no, pv.release_date
              FROM package_version pv JOIN package pk USING (package_id)"""):
    key = f"{r['name']}@{r['version_no']}"
    vid[r["version_id"]] = key
    comps[key] = {"_id": key, "package": r["name"], "ecosystem": r["ecosystem"],
                  "version": r["version_no"], "release_date": clean(r["release_date"]),
                  "depends_on": []}
for r in q("SELECT parent_version_id p, child_version_id c FROM package_dependency"):
    comps[vid[r["p"]]]["depends_on"].append(vid[r["c"]])
db.components.insert_many(list(comps.values()))

# ---------- projects with embedded direct dependencies ----------
projects = {}
for r in q("""SELECT p.project_id, p.name, p.language, p.criticality, u.full_name owner, u.email owner_email
              FROM project p JOIN app_user u ON u.user_id = p.owner_id"""):
    projects[r["project_id"]] = {"_id": r["name"], "owner": r["owner"], "owner_email": r["owner_email"],
                                 "language": r["language"], "criticality": r["criticality"],
                                 "direct_deps": []}
for r in q("SELECT project_id, version_id FROM project_dependency"):
    projects[r["project_id"]]["direct_deps"].append(vid[r["version_id"]])
db.projects.insert_many(list(projects.values()))

# ---------- vulnerabilities with embedded affected versions and patches ----------
vulns = {}
for r in q("SELECT * FROM vulnerability"):
    vulns[r["vuln_id"]] = {"_id": r["cve_id"], "cve_id": r["cve_id"],
                           "description": r["description"], "cvss": clean(r["cvss_score"]),
                           "severity": r["severity"], "published": clean(r["published_date"]),
                           "affected": [], "patches": []}
for r in q("SELECT vuln_id, version_id FROM vulnerability_affected"):
    vulns[r["vuln_id"]]["affected"].append(vid[r["version_id"]])
for r in q("SELECT vuln_id, fixed_version_id, notes FROM patch"):
    vulns[r["vuln_id"]]["patches"].append({"fixed_in": vid[r["fixed_version_id"]], "notes": r["notes"]})
db.vulnerabilities.insert_many(list(vulns.values()))

# ---------- remediation ----------
pname = {k: v["_id"] for k, v in projects.items()}
cve = {k: v["cve_id"] for k, v in vulns.items()}
docs = [{"project": pname[r["project_id"]], "cve_id": cve[r["vuln_id"]],
         "status": r["status"], "assigned_to": r["assigned_to"],
         "resolved_at": clean(r["resolved_at"])}
        for r in q("SELECT * FROM remediation")]
if docs:
    db.remediation.insert_many(docs)

# ---------- a few starter analyst notes (flexible schema: tags only on some) ----------
now = datetime.now(timezone.utc)
db.analyst_notes.insert_many([
    {"cve_id": "CVE-2021-44228", "text": "Log4Shell is actively exploited. Patch PaymentService first.",
     "author": "meera@example.com", "tags": ["exploited", "urgent"], "created_at": now},
    {"cve_id": "CVE-2023-25577", "text": "No upstream patch yet. Limit multipart upload size as a workaround.",
     "author": "meera@example.com", "created_at": now},
])

# ---------- indexes ----------
db.remediation.create_index([("project", 1), ("cve_id", 1)], unique=True)
db.vulnerabilities.create_index("severity")
db.analyst_notes.create_index("cve_id")
db.components.create_index("depends_on")

print({c: db[c].count_documents({}) for c in db.list_collection_names()})
