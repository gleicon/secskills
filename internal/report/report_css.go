package report

// reportCSS is the print-optimized, big-4 corporate stylesheet for the HTML/PDF
// report. Deliberately dependency-free (no web fonts) so PDF rendering is stable.
const reportCSS = `
:root{
  --navy:#12233f; --navy2:#1c3a63; --slate:#334155; --muted:#64748b;
  --line:#dbe2ea; --bg:#ffffff; --soft:#f5f7fa;
  --crit:#7a0b1e; --high:#c0392b; --med:#c8860b; --low:#2b8ac6; --info:#64748b;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;color:var(--slate);background:var(--bg);
  font-family:'Helvetica Neue',Arial,'Segoe UI',sans-serif;font-size:11pt;line-height:1.5}
h1{font-size:30pt;margin:0 0 6pt;color:#fff;font-weight:700;letter-spacing:.2px}
h2{font-size:17pt;color:var(--navy);border-bottom:2.5px solid var(--navy);
  padding-bottom:5px;margin:0 0 14px}
h3{font-size:12.5pt;color:var(--navy2);margin:16px 0 7px}
p{margin:0 0 9px}
code{background:var(--soft);padding:1px 4px;border-radius:3px;font-family:'SF Mono',Menlo,Consolas,monospace;font-size:9.5pt}
pre{background:#0f1b2d;color:#e6edf5;padding:10px 12px;border-radius:5px;
  font-family:'SF Mono',Menlo,Consolas,monospace;font-size:9pt;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.note{color:var(--muted);font-size:9.5pt;font-style:italic}

/* page structure */
.page{padding:26px 34px 40px}
.page{page-break-before:always}
section.cover{page-break-after:always}

/* cover */
.cover{height:96vh;background:linear-gradient(150deg,var(--navy) 0%,var(--navy2) 100%);
  color:#fff;padding:40px 44px;display:flex;flex-direction:column}
.cover-top{display:flex;justify-content:space-between;align-items:center}
.brand{font-weight:800;font-size:18pt;letter-spacing:1px}
.classif{border:1.5px solid #fff;border-radius:3px;padding:3px 10px;font-size:9pt;letter-spacing:2px}
.cover-mid{margin-top:34vh}
.doctype{text-transform:uppercase;letter-spacing:3px;font-size:11pt;opacity:.85;margin-bottom:10px}
.cover-sub{opacity:.85;font-size:12pt;margin-top:6px}
.cover-meta{margin-top:auto;border-collapse:collapse;color:#dbe6f5;font-size:10pt}
.cover-meta td{padding:4px 0}
.cover-meta td:first-child{opacity:.7;width:170px;text-transform:uppercase;letter-spacing:.5px;font-size:8.5pt}
.cover-foot{margin-top:14px;font-size:8.5pt;opacity:.65;border-top:1px solid rgba(255,255,255,.25);padding-top:10px}

/* tables */
table.grid{width:100%;border-collapse:collapse;margin:8px 0 14px;font-size:10pt}
table.grid th{background:var(--navy);color:#fff;text-align:left;padding:7px 9px;font-weight:600;font-size:9.5pt}
table.grid td{border:1px solid var(--line);padding:6px 9px;vertical-align:top}
table.grid tr:nth-child(even) td{background:var(--soft)}
.findings-tbl td:first-child{white-space:nowrap;font-weight:600}

/* severity */
.pill{display:inline-block;color:#fff;border-radius:3px;padding:1.5px 7px;font-size:8.5pt;font-weight:700;letter-spacing:.5px}
.sev-critical{background:var(--crit)} .sev-high{background:var(--high)}
.sev-medium{background:var(--med)} .sev-low{background:var(--low)} .sev-informational{background:var(--info)}

/* heat cells */
.heat{display:flex;gap:8px;margin:8px 0 4px}
.heat-cell{flex:1;color:#fff;border-radius:5px;padding:12px 8px;text-align:center}
.heat-cell.total{background:var(--navy)}
.hc-n{font-size:22pt;font-weight:800;line-height:1}
.hc-l{font-size:8pt;letter-spacing:1px;margin-top:4px;opacity:.9}

/* key findings */
ul.keys{list-style:none;padding:0;margin:6px 0}
ul.keys li{padding:6px 0;border-bottom:1px solid var(--line)}
ul.keys .host{color:var(--muted);font-size:9pt}

/* findings */
.finding{border:1px solid var(--line);border-radius:6px;margin:0 0 16px;padding:0;page-break-inside:avoid}
.f-head{display:flex;align-items:center;gap:10px;background:var(--soft);
  border-bottom:1px solid var(--line);padding:9px 12px;border-radius:6px 6px 0 0}
.f-head h3{margin:0;color:var(--navy)}
.fid{font-weight:800;color:var(--navy2);font-size:10pt}
.f-meta{margin:10px 12px}
.f-meta td:first-child{width:180px;color:var(--muted);font-size:9pt;text-transform:uppercase;letter-spacing:.3px}
.f-body{padding:0 12px 12px}
.rem{background:var(--soft);border-left:3px solid var(--navy);padding:8px 12px;margin:6px 0;font-size:9.5pt}
.rem ul{margin:4px 0;padding-left:18px}.rem code{font-size:9pt}

.doc-foot{margin-top:20px;padding:12px 34px;color:var(--muted);font-size:8.5pt;border-top:1px solid var(--line);text-align:center}

@page{size:A4;margin:16mm 0}
@media print{
  .heat-cell,.pill,table.grid th{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .finding,tr,section{page-break-inside:avoid}
}
`
