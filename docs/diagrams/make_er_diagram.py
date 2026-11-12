# Generates the Chen-notation ER diagram with Graphviz (neato, pinned layout)
import subprocess
E = {  # entity: (x, y, weak)
 "APP_USER": (2, 12, False), "PROJECT": (2, 5, False), "REMEDIATION": (14, 12, False),
 "VULNERABILITY": (21, 5.5, False), "PACKAGE_VERSION": (11.5, 0, True), "PACKAGE": (2, -3.5, False),
 "PATCH": (21, -3.5, False), "AUDIT_LOG": (23.5, 13, False),
}
R = {  # relationship: (x, y, identifying)
 "OWNS": (2, 8.6, False), "ASSIGNED_TO": (8, 12, False), "FOR_PROJECT": (8, 8.6, False),
 "FOR_CVE": (17.5, 8.8, False), "DEPENDS_ON": (6.5, 2.5, False), "AFFECTS": (16.5, 2.8, False),
 "HAS_VERSION": (6.5, -1.8, True), "REQUIRES": (11.5, -4.2, False), "FIXES": (21, 1, False),
 "FIXED_IN": (16.5, -2, False),
}
# links: (entity, rel, cardinality, total_participation, role)
L = [
 ("APP_USER","OWNS","1",False,""), ("PROJECT","OWNS","N",True,""),
 ("APP_USER","ASSIGNED_TO","1",False,""), ("REMEDIATION","ASSIGNED_TO","N",False,""),
 ("PROJECT","FOR_PROJECT","1",False,""), ("REMEDIATION","FOR_PROJECT","N",True,""),
 ("VULNERABILITY","FOR_CVE","1",False,""), ("REMEDIATION","FOR_CVE","N",True,""),
 ("PROJECT","DEPENDS_ON","M",False,""), ("PACKAGE_VERSION","DEPENDS_ON","N",False,""),
 ("VULNERABILITY","AFFECTS","M",True,""), ("PACKAGE_VERSION","AFFECTS","N",False,""),
 ("PACKAGE","HAS_VERSION","1",False,""), ("PACKAGE_VERSION","HAS_VERSION","N",True,""),
 ("PACKAGE_VERSION","REQUIRES","M",False,"parent"), ("PACKAGE_VERSION","REQUIRES","N",False,"child"),
 ("VULNERABILITY","FIXES","1",False,""), ("PATCH","FIXES","N",True,""),
 ("PACKAGE_VERSION","FIXED_IN","1",False,""), ("PATCH","FIXED_IN","N",True,""),
]
# attributes: owner -> list of (name, kind)  kind: key | pkey (partial) | derived | plain
A = {
 "APP_USER": [("user_id","key"),("full_name",""),("email",""),("role",""),("password_hash",""),("created_at","")],
 "PROJECT": [("project_id","key"),("name",""),("repo_url",""),("language",""),("criticality",""),("created_at",""),("risk_score","derived")],
 "PACKAGE": [("package_id","key"),("name",""),("ecosystem",""),("maintainer","")],
 "PACKAGE_VERSION": [("version_no","pkey"),("release_date",""),("is_deprecated","")],
 "VULNERABILITY": [("vuln_id","key"),("cve_id",""),("description",""),("cvss_score",""),("severity","derived"),("published_date","")],
 "PATCH": [("patch_id","key"),("release_date",""),("notes","")],
 "REMEDIATION": [("remediation_id","key"),("status",""),("due_date",""),("resolved_at","")],
 "AUDIT_LOG": [("log_id","key"),("table_name",""),("operation",""),("record_id",""),("old_data",""),("new_data",""),("changed_by",""),("changed_at","")],
 "DEPENDS_ON": [("added_at","")],
}
OFF = {
 "APP_USER": [(-2.4,1.0),(-1.0,1.6),(0.6,1.7),(2.2,1.4),(-2.9,-0.2),(-2.2,-1.2)],
 "PROJECT": [(-1.4,1.6),(-2.9,0.6),(-3.0,-0.3),(-2.7,-1.2),(-1.5,-1.9),(0.1,-2.1),(-3.0,1.5)],
 "PACKAGE": [(-2.4,0.9),(-2.8,0),(-2.4,-0.9),(0.4,-1.3)],
 "PACKAGE_VERSION": [(-1.4,1.7),(0.1,2.0),(1.5,1.8)],
 "VULNERABILITY": [(1.0,1.6),(3.0,0.6),(3.0,-0.3),(2.7,-1.2),(2.4,1.5),(-2.6,0.3)],
 "PATCH": [(2.6,0.5),(0.5,-1.3),(2.6,-0.5)],
 "REMEDIATION": [(-1.7,1.4),(-0.2,1.7),(1.3,1.5),(2.6,0.6)],
 "AUDIT_LOG": [(-2.6,0.4),(-2.3,-0.8),(-0.8,-1.4),(0.8,-1.4),(2.4,-0.8),(2.7,0.3),(1.7,1.3),(-0.6,1.4)],
 "DEPENDS_ON": [(-2.0,-0.4)],
}
out = ['graph ER {', 'graph [splines=line, outputorder=edgesfirst, bgcolor="white", pad=0.3];',
       'node [fontname="Helvetica", fontsize=13];', 'edge [color="#333333", fontname="Helvetica", fontsize=13];']
pos = {}
for n,(x,y,weak) in E.items():
    pos[n]=(x,y)
    out.append(f'{n} [shape=box, style="filled", fillcolor="#E8F0F7", color="#1F3A5F", penwidth=1.6, {"peripheries=2," if weak else ""} label="{n}", pos="{x},{y}!", width=1.9, height=0.55, fontname="Helvetica-Bold"];')
for n,(x,y,ident) in R.items():
    pos[n]=(x,y)
    out.append(f'{n} [shape=diamond, style=filled, fillcolor="#FFF6E5", color="#8A5A00", penwidth=1.4, {"peripheries=2," if ident else ""} label="{n}", pos="{x},{y}!", width=2.1, height=0.9, fontsize=11];')
for (e,r,card,total,role) in L:
    style = 'color="#333333:white:#333333"' if total else ''
    ports = ''
    if role=="parent": ports='tailport=sw, headport=w,'
    if role=="child": ports='tailport=se, headport=e,'
    lab = card + (f" ({role})" if role else "")
    out.append(f'{e} -- {r} [{ports} {style} label="{lab}", fontcolor="#B00020"];')
k=0
for owner, attrs in A.items():
    x0,y0 = pos[owner]
    for (name,kind),(dx,dy) in zip(attrs, OFF[owner]):
        x=x0+dx; y=y0+dy
        nid=f"a{k}"; k+=1
        if kind=="key": lbl=f'<<u>{name}</u>>'
        elif kind=="pkey": lbl=f'<<u>{name}</u><br/><font point-size="9">(partial key)</font>>'
        else: lbl=f'"{name}"'
        st = 'style="dashed,filled"' if kind=="derived" else 'style=filled'
        out.append(f'{nid} [shape=ellipse, {st}, fillcolor="white", color="#555555", label={lbl}, pos="{x:.2f},{y:.2f}!", fontsize=11, margin="0.04,0.02"];')
        out.append(f'{owner} -- {nid} [color="#777777"];')
out.append('auditnote [shape=plaintext, fontsize=10, fontcolor="#555555", label="Stand-alone: filled by triggers,\nno relationship by design", pos="23.5,11.0!"];')
# legend
out.append('legend [shape=plaintext, pos="24.3,-6.3!", label=<<table border="1" cellborder="0" cellspacing="2" cellpadding="3" color="#999999"><tr><td colspan="2"><b>Legend</b></td></tr>'
 '<tr><td align="left">Double box</td><td align="left">Weak entity</td></tr>'
 '<tr><td align="left">Double diamond</td><td align="left">Identifying relationship</td></tr>'
 '<tr><td align="left">Double line</td><td align="left">Total participation</td></tr>'
 '<tr><td align="left">Underlined</td><td align="left">Key attribute</td></tr>'
 '<tr><td align="left">Dashed ellipse</td><td align="left">Derived attribute</td></tr>'
 '<tr><td align="left">Red 1 / M / N</td><td align="left">Cardinality</td></tr></table>>];')
out.append('title [shape=plaintext, fontsize=20, fontname="Helvetica-Bold", label="Software Supply-Chain Vulnerability Management: ER Diagram", pos="11,15.3!"];')
out.append('}')
open("docs/diagrams/er.dot","w").write("\n".join(out))
subprocess.run(["neato","-n2","-Tpng","-Gdpi=150","-o","docs/diagrams/er.png","docs/diagrams/er.dot"],check=False)
subprocess.run(["neato","-Tpng","-Gdpi=150","-o","docs/diagrams/er.png","docs/diagrams/er.dot"],check=True)
subprocess.run(["neato","-Tsvg","-o","docs/diagrams/er.svg","docs/diagrams/er.dot"],check=True)
