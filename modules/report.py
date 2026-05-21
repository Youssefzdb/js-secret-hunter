#!/usr/bin/env python3
"""HTML Report v2 - Detailed, filterable, with entropy scores"""
from datetime import datetime

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#facc15", "LOW": "#94a3b8"}
SEV_BG    = {"CRITICAL": "#2d0a0a", "HIGH": "#2d1500", "MEDIUM": "#2d2500", "LOW": "#1a1a2e"}

class SecretReport:
    def __init__(self, target, js_files, findings):
        self.target = target
        self.js_files = js_files
        self.findings = sorted(findings, key=lambda x: SEV_ORDER.index(x.get("severity","LOW")))

    def save(self, filename):
        counts = {s: len([f for f in self.findings if f["severity"]==s]) for s in SEV_ORDER}

        rows = ""
        for f in self.findings:
            sev = f["severity"]
            color = SEV_COLOR[sev]
            bg = SEV_BG.get(sev, "#1a1a2e")
            decoded_html = f'<br><small style="color:#a78bfa;font-size:11px">🔓 {f["decoded"][:150]}</small>' if f.get("decoded") else ""
            snippet_html = f'<br><small style="color:#64748b;font-size:10px">{f.get("snippet","")[:100]}</small>'
            rows += f"""<tr style="background:{bg}">
              <td style="color:{color};font-weight:bold;white-space:nowrap">{sev}</td>
              <td style="white-space:nowrap">{f["type"]}</td>
              <td><code style="font-size:11px;word-break:break-all">{f["value"][:100]}</code>{decoded_html}{snippet_html}</td>
              <td style="white-space:nowrap"><small style="color:#64748b">{f.get("source","")[:40]}</small></td>
              <td style="text-align:center"><small style="color:{'#ef4444' if f.get('entropy',0)>3.5 else '#94a3b8'}">{f.get("entropy","?")}</small></td>
            </tr>"""

        js_list = "".join(
            f'<li style="margin:2px 0"><code style="font-size:11px;color:#64748b">{url[:100]}</code> <span style="color:#475569">({len(c):,}b)</span></li>'
            for url, c in list(self.js_files.items())[:50]
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>JS Secret Hunter v2 — {self.target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#060612;color:#e2e0ff;padding:24px;font-size:14px}}
  h1{{color:#a78bfa;font-size:1.6em;margin-bottom:4px}}
  h2{{color:#c4b5fd;font-size:1.1em;margin:20px 0 8px}}
  .meta{{color:#64748b;font-size:12px;margin-bottom:16px}}
  .stats{{display:flex;gap:10px;margin:16px 0;flex-wrap:wrap}}
  .stat{{background:#0f0f1e;border-radius:8px;padding:12px 18px;text-align:center;border:1px solid #1e1e3a;min-width:90px}}
  .stat .n{{font-size:2em;font-weight:bold;line-height:1.1}}
  .stat .l{{font-size:11px;color:#64748b;margin-top:2px}}
  .banner{{background:#2d0a0a;border:1px solid #ef4444;border-radius:8px;padding:10px 14px;margin:12px 0;color:#fca5a5;font-size:13px}}
  .card{{background:#0d0d1c;border-radius:8px;padding:16px;margin:12px 0;border:1px solid #1e1e3a}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  td,th{{padding:7px 10px;border-bottom:1px solid #0f0f1c;vertical-align:top}}
  th{{background:#0a0a18;color:#a5b4fc;font-weight:600;white-space:nowrap}}
  tr:hover td{{background:#111128}}
  code{{font-family:'Courier New',monospace;color:#a78bfa}}
  ul{{list-style:none;max-height:180px;overflow-y:auto;background:#080814;padding:8px 12px;border-radius:6px}}
  .empty{{text-align:center;color:#22c55e;padding:20px}}
</style></head>
<body>
<h1>🔍 JS Secret Hunter v2</h1>
<p class="meta">Target: <strong>{self.target}</strong> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; For authorized penetration testing only</p>

<div class="stats">
  <div class="stat"><div class="n" style="color:#ef4444">{counts['CRITICAL']}</div><div class="l">CRITICAL</div></div>
  <div class="stat"><div class="n" style="color:#f97316">{counts['HIGH']}</div><div class="l">HIGH</div></div>
  <div class="stat"><div class="n" style="color:#facc15">{counts['MEDIUM']}</div><div class="l">MEDIUM</div></div>
  <div class="stat"><div class="n" style="color:#94a3b8">{counts['LOW']}</div><div class="l">LOW</div></div>
  <div class="stat"><div class="n" style="color:#a78bfa">{len(self.findings)}</div><div class="l">TOTAL</div></div>
  <div class="stat"><div class="n" style="color:#22c55e">{len(self.js_files)}</div><div class="l">JS FILES</div></div>
</div>

{"<div class='banner'>🚨 CRITICAL secrets detected — immediate remediation required!</div>" if counts['CRITICAL'] > 0 else ""}

<div class="card">
  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Type</th><th>Value / Decoded</th><th>Source</th><th>Entropy</th></tr>
    {''.join([rows]) if rows else '<tr><td colspan=5 class="empty">✅ No secrets detected — target appears clean</td></tr>'}
  </table>
</div>

<div class="card">
  <h2>JS & Source Files Scanned ({len(self.js_files)})</h2>
  <ul>{js_list}</ul>
</div>
</body></html>"""

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Report saved: {filename}")
