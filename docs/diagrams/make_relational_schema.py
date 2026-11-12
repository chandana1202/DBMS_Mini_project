import subprocess
T = {  # table: (is_er_entity, [(col, type, flags)])  flags: PK, FK, UQ, NN
 "app_user": (True, [("user_id","INT","PK"),("full_name","VARCHAR(100)","NN"),("email","VARCHAR(150)","UQ NN"),("role","ENUM","NN"),("password_hash","VARCHAR(100)",""),("created_at","TIMESTAMP","NN")]),
 "project": (True, [("project_id","INT","PK"),("name","VARCHAR(100)","UQ NN"),("owner_id","INT","FK NN"),("repo_url","VARCHAR(255)",""),("language","VARCHAR(30)",""),("criticality","ENUM","NN"),("created_at","TIMESTAMP","NN")]),
 "package": (True, [("package_id","INT","PK"),("name","VARCHAR(150)","UQ* NN"),("ecosystem","ENUM","UQ* NN"),("maintainer","VARCHAR(100)","")]),
 "package_version": (True, [("version_id","INT","PK"),("package_id","INT","FK UQ* NN"),("version_no","VARCHAR(30)","UQ* NN"),("release_date","DATE",""),("is_deprecated","BOOLEAN","NN")]),
 "project_dependency": (False, [("project_id","INT","PK FK"),("version_id","INT","PK FK"),("added_at","TIMESTAMP","NN")]),
 "package_dependency": (False, [("parent_version_id","INT","PK FK"),("child_version_id","INT","PK FK")]),
 "vulnerability": (True, [("vuln_id","INT","PK"),("cve_id","VARCHAR(20)","UQ NN"),("description","TEXT",""),("cvss_score","DECIMAL(3,1)",""),("severity","ENUM",""),("published_date","DATE","NN")]),
 "vulnerability_affected": (False, [("vuln_id","INT","PK FK"),("version_id","INT","PK FK")]),
 "patch": (True, [("patch_id","INT","PK"),("vuln_id","INT","FK UQ* NN"),("fixed_version_id","INT","FK UQ* NN"),("release_date","DATE",""),("notes","VARCHAR(255)","")]),
 "remediation": (True, [("remediation_id","INT","PK"),("project_id","INT","FK UQ* NN"),("vuln_id","INT","FK UQ* NN"),("status","ENUM","NN"),("assigned_to","INT","FK"),("due_date","DATE",""),("resolved_at","DATETIME","")]),
 "audit_log": (True, [("log_id","BIGINT","PK"),("table_name","VARCHAR(50)","NN"),("operation","ENUM","NN"),("record_id","INT",""),("old_data","JSON",""),("new_data","JSON",""),("changed_by","VARCHAR(100)",""),("changed_at","TIMESTAMP","NN")]),
}
FKS = [  # (table, col, ref_table, ref_col, on_delete)
 ("project","owner_id","app_user","user_id",""),
 ("package_version","package_id","package","package_id","CASCADE"),
 ("project_dependency","project_id","project","project_id","CASCADE"),
 ("project_dependency","version_id","package_version","version_id",""),
 ("package_dependency","parent_version_id","package_version","version_id",""),
 ("package_dependency","child_version_id","package_version","version_id",""),
 ("vulnerability_affected","vuln_id","vulnerability","vuln_id","CASCADE"),
 ("vulnerability_affected","version_id","package_version","version_id","CASCADE"),
 ("patch","vuln_id","vulnerability","vuln_id","CASCADE"),
 ("patch","fixed_version_id","package_version","version_id",""),
 ("remediation","project_id","project","project_id","CASCADE"),
 ("remediation","vuln_id","vulnerability","vuln_id","CASCADE"),
 ("remediation","assigned_to","app_user","user_id","SET NULL"),
]
CHECKS = {
 "app_user": "CHECK email LIKE '%_@_%._%'",
 "package_version": "CHECK CHAR_LENGTH(version_no) &gt; 0",
 "package_dependency": "CHECK parent &lt;&gt; child",
 "vulnerability": "CHECK cve_id REGEXP '^CVE-…', CHECK cvss_score 0 to 10",
 "remediation": "CHECK RESOLVED needs resolved_at",
}
out=['digraph RS {','graph [rankdir=LR, bgcolor="white", nodesep=0.35, ranksep=1.3, pad=0.4, fontname="Helvetica", splines=true, label=<<b>Software Supply-Chain Vulnerability Management: Relational Schema (MySQL, 3NF)</b>>, labelloc=t, fontsize=22];',
     'node [shape=plain, fontname="Helvetica"];','edge [color="#4A5A70", arrowhead=normal, arrowtail=none, penwidth=1.2, fontname="Helvetica", fontsize=10, fontcolor="#7A4A00"];']
OD={(t,c):od for t,c,rt,rc,od in FKS if od}
for t,(ent,cols) in T.items():
    cols=[(c,ty,fl+(" <i>del:"+OD[(t,c)].lower()+"</i>" if (t,c) in OD else "")) for c,ty,fl in cols]
    head = "#1F3A5F" if ent else "#7A4A00"
    rows=[f'<tr><td colspan="3" bgcolor="{head}"><font color="white"><b>{t}</b></font></td></tr>']
    for c,ty,fl in cols:
        name = f"<b><u>{c}</u></b>" if "PK" in fl else (f"<i>{c}</i>" if "FK" in fl else c)
        bg = "#EEF3F8" if "PK" in fl else "white"
        rows.append(f'<tr><td align="left" port="{c}" bgcolor="{bg}">{name}</td><td align="left" bgcolor="{bg}"><font color="#555555">{ty}</font></td><td align="left" port="{c}_r" bgcolor="{bg}">{("<font color=\"#1F3A5F\" point-size=\"10\">"+fl+"</font>") if fl else " "}</td></tr>')
    if t in CHECKS:
        rows.append(f'<tr><td colspan="3" align="left" bgcolor="#FAFAFA"><font point-size="9" color="#666666">{CHECKS[t]}</font></td></tr>')
    out.append(f'{t} [label=<<table border="1" cellborder="1" cellspacing="0" cellpadding="4" color="#9AA5B1">{"".join(rows)}</table>>];')
for t,c,rt,rc,od in FKS:
    lab = f"ON DELETE {od}" if od else ""
    out.append(f'{t}:{c}_r:e -> {rt}:{rc}:w;')
out.append('legend [label=<<table border="1" cellborder="0" cellspacing="2" cellpadding="4" color="#9AA5B1"><tr><td colspan="2"><b>Legend</b></td></tr>'
 '<tr><td bgcolor="#1F3A5F" width="20"></td><td align="left">Relation from an ER entity</td></tr>'
 '<tr><td bgcolor="#7A4A00" width="20"></td><td align="left">Relation from an M:N relationship (not an entity)</td></tr>'
 '<tr><td align="left"><b><u>col</u></b></td><td align="left">Primary key</td></tr>'
 '<tr><td align="left"><i>col</i></td><td align="left">Foreign key (arrow points to referenced key)</td></tr>'
 '<tr><td align="left">UQ / UQ*</td><td align="left">Unique / part of composite unique</td></tr>'
 '<tr><td align="left">NN</td><td align="left">NOT NULL</td></tr><tr><td align="left"><i>del:…</i></td><td align="left">ON DELETE action of the foreign key</td></tr></table>>];')
out.append('}')
open('rs.dot','w').write("\n".join(out))
subprocess.run(["dot","-Tpng","-Gdpi=150","-o","rs.png","rs.dot"],check=True)
subprocess.run(["dot","-Tsvg","-o","rs.svg","rs.dot"],check=True)
