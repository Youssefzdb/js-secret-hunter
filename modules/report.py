#!/usr/bin/env python3
"""HTML Report Generator"""
from datetime import datetime

SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#facc15",
    "LOW":      "#94a3b8"
}

class SecretReport:
    def __init__(self, target, js_files, findings):
        self.target = target
        self.js_files = js_files
        self.findings = findings

    def save(self, filename):
        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high     = [f for f in self.findings if f["severity"] == "HIGH"]

        rows = ""
        for f in sorted(self.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"])):
            color = SEV_COLOR.get(f["severity"], "#888")
            decoded_html = f"<br><small style='color:#a78bfa'>🔓 {f['decoded']}</small>" if f.get("decoded") else ""
            rows += f"""<tr>
              <td style="color:{color};font-weight:bold">{f['severity']}</td>
              <td>{f['type']}</td>
              <td><code>{f['value'][:80]}</code>{decoded_html}</td>
              <td><small>{f['source']}</small></td>
            </tr>"""

        js_list = "".join(f"<li><code>{url}</code> ({len(content):,} bytes)</li>"
                          for url, content in list(self.js_files.items())[:30])

        html = f"""<!DOCTYPE html><html><head>
<title>JS Secret Hunter Report</title>
<style>
  body{{font-family:Arial,sans-serif;background:#0a0a14;color:#e2e0ff;padding:24px;margin:0}}
  h1{{color:#a78bfa;margin-bottom:4px}} h2{{color:#c4b5fd;margin-top:24px}}
  .stats{{display:flex;gap:12px;margin:16px 0}}
  .stat{{background:#1e1b2e;border-radius:8px;padding:12px 20px;text-align:center;border:1px solid #2d2b45}}
  .stat .n{{font-size:2em;font-weight:bold}}
  .banner{{background:#2d1b00;border:1px solid #f97316;border-radius:8px;padding:12px;margin:12px 0;color:#fed7aa}}
  table{{width:100%;border-collapse:collapse;margin:8px 0}}
  td,th{{padding:8px 10px;border:1px solid #1e1e3a;vertical-align:top}}
  th{{background:#1a1a3a;color:#a5b4fc}} code{{color:#a78bfa;font-size:12px;word-break:break-all}}
  ul{{max-height:200px;overflow-y:auto;background:#111;padding:10px 24px;border-radius:6px}}
  li{{font-size:12px;color:#94a3b8;margin:2px 0}}
</style></head><body>
<h1>🔍 JS Secret Hunter Report</h1>
<p style="color:#64748b">{self.target} | {datetime.now().strftime('%Y-%m-%d %H:%M')} | For authorized penetration testing only</p>

<div class="stats">
  <div class="stat"><div class="n" style="color:#ef4444">{len(critical)}</div><div>CRITICAL</div></div>
  <div class="stat"><div class="n" style="color:#f97316">{len(high)}</div><div>HIGH</div></div>
  <div class="stat"><div class="n" style="color:#a78bfa">{len(self.findings)}</div><div>TOTAL</div></div>
  <div class="stat"><div class="n" style="color:#22c55e">{len(self.js_files)}</div><div>JS FILES</div></div>
</div>

{"<div class='banner'>⚠️ CRITICAL secrets found — review immediately!</div>" if critical else ""}

<h2>Findings</h2>
<table>
  <tr><th>Severity</th><th>Type</th><th>Value / Decoded</th><th>Source File</th></tr>
  {rows if rows else '<tr><td colspan=4 style="text-align:center;color:#22c55e">✅ No secrets detected</td></tr>'}
</table>

<h2>JS Files Scanned ({len(self.js_files)})</h2>
<ul>{js_list}</ul>
</body></html>"""

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Report saved: {filename}")
