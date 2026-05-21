#!/usr/bin/env python3
"""Report v3 - Detailed HTML report with severity breakdown + copy buttons"""
from datetime import datetime
import json

SEV_COLOR = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#facc15","LOW":"#94a3b8"}
SEV_BG    = {"CRITICAL":"#2d0a0a","HIGH":"#2d1500","MEDIUM":"#2d2200","LOW":"#1a1a2e"}

class SecretReport:
    def __init__(self, target, js_files, findings):
        self.target = target
        self.js_files = js_files
        self.findings = findings

    def _build_finding_rows(self):
        rows = ""
        sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]
        sorted_findings = sorted(
            self.findings,
            key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 99
        )
        for i, f in enumerate(sorted_findings):
            color = SEV_COLOR.get(f["severity"], "#888")
            bg = SEV_BG.get(f["severity"], "#111")
            decoded_html = ""
            if f.get("decoded"):
                d = f["decoded"]
                fmt = d.get("format", "")
                text = d.get("text", "")[:200].replace("<","&lt;").replace(">","&gt;")
                # If JWT, show payload fields
                if fmt == "JWT" and d.get("payload"):
                    payload_str = json.dumps(d["payload"], ensure_ascii=False)[:200]
                    text = f"alg={d.get('algorithm','?')} | {payload_str}"
                decoded_html = f"""
                <div style="margin-top:6px;padding:6px 8px;background:#0f0f1a;border-radius:4px;border-left:2px solid #6366f1">
                  <small style="color:#6366f1">🔓 {fmt}</small>
                  <br><code style="color:#a5b4fc;font-size:11px;word-break:break-all">{text}</code>
                </div>"""

            snippet = f.get("snippet","")[:100].replace("<","&lt;").replace(">","&gt;")
            value_display = f["value"][:100].replace("<","&lt;").replace(">","&gt;")
            src_url = f.get("source_url","")
            src_display = f.get("source","")[:50]

            rows += f"""
            <tr style="background:{bg}" id="finding-{i}">
              <td style="text-align:center">
                <span style="background:{color};color:#000;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold">
                  {f["severity"]}
                </span>
              </td>
              <td style="color:#e2e0ff;font-weight:bold">{f["type"]}</td>
              <td>
                <code style="color:#fbbf24;font-size:12px;word-break:break-all">{value_display}</code>
                {decoded_html}
                <div style="margin-top:4px"><small style="color:#475569">📄 {snippet}</small></div>
              </td>
              <td>
                <a href="{src_url}" target="_blank" style="color:#6366f1;font-size:11px">{src_display}</a>
                <br><small style="color:#475569">Line {f.get("line","?")}</small>
              </td>
            </tr>"""
        return rows

    def save(self, filename):
        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        rows = self._build_finding_rows()
        js_list = "".join(
            f'<li><a href="{url}" target="_blank" style="color:#6366f1">{url.split("/")[-1][:60]}</a> <small style="color:#475569">({len(c):,} bytes)</small></li>'
            for url, c in list(self.js_files.items())[:50]
        )

        risk_score = counts.get("CRITICAL",0)*10 + counts.get("HIGH",0)*5 + counts.get("MEDIUM",0)*2 + counts.get("LOW",0)
        risk_level = "CRITICAL" if risk_score >= 10 else "HIGH" if risk_score >= 5 else "MEDIUM" if risk_score >= 2 else "CLEAN"
        risk_color = SEV_COLOR.get(risk_level, "#22c55e")

        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>JS Secret Hunter v3 — {self.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #070711; color: #e2e0ff; padding: 24px; }}
  h1 {{ color: #a78bfa; font-size: 1.6em; margin-bottom: 4px; }}
  h2 {{ color: #c4b5fd; font-size: 1.1em; margin: 20px 0 10px; border-bottom: 1px solid #1e1e3a; padding-bottom: 6px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 16px; }}
  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }}
  .stat {{ background: #13132a; border-radius: 10px; padding: 14px 22px; text-align: center; border: 1px solid #2d2b45; min-width: 100px; }}
  .stat .n {{ font-size: 2.2em; font-weight: bold; line-height: 1.1; }}
  .stat .l {{ font-size: 12px; color: #94a3b8; margin-top: 2px; }}
  .risk-badge {{ display: inline-block; padding: 6px 18px; border-radius: 20px; font-weight: bold; font-size: 1.1em; background: {risk_color}22; color: {risk_color}; border: 1px solid {risk_color}; }}
  .banner {{ background: #2d0a0a; border: 1px solid #ef4444; border-radius: 8px; padding: 12px 16px; margin: 12px 0; color: #fca5a5; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #1a1a3a; color: #a5b4fc; padding: 10px 12px; text-align: left; position: sticky; top: 0; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a1a2e; vertical-align: top; }}
  code {{ font-family: 'Consolas','Courier New',monospace; }}
  ul {{ list-style: none; padding: 0; max-height: 220px; overflow-y: auto; background: #0f0f1a; border-radius: 6px; padding: 8px 12px; }}
  li {{ padding: 3px 0; font-size: 12px; border-bottom: 1px solid #1a1a2e; }}
  .section {{ background: #0d0d1f; border-radius: 10px; padding: 16px; margin: 12px 0; border: 1px solid #1e1e3a; }}
  .filter-bar {{ margin-bottom: 10px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 4px 14px; border-radius: 20px; border: 1px solid #2d2b45; background: #13132a; color: #94a3b8; cursor: pointer; font-size: 12px; }}
  .filter-btn.active {{ background: #4f46e5; color: #fff; border-color: #4f46e5; }}
</style>
</head><body>

<h1>🔍 JS Secret Hunter <span style="color:#6366f1;font-size:0.7em">v3</span></h1>
<p class="meta">
  Target: <strong style="color:#e2e0ff">{self.target}</strong> &nbsp;|&nbsp;
  {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
  JS Files: <strong>{len(self.js_files)}</strong> &nbsp;|&nbsp;
  Risk: <span class="risk-badge">{risk_level}</span>
</p>

<div class="stats">
  <div class="stat"><div class="n" style="color:{SEV_COLOR['CRITICAL']}">{counts.get('CRITICAL',0)}</div><div class="l">CRITICAL</div></div>
  <div class="stat"><div class="n" style="color:{SEV_COLOR['HIGH']}">{counts.get('HIGH',0)}</div><div class="l">HIGH</div></div>
  <div class="stat"><div class="n" style="color:{SEV_COLOR['MEDIUM']}">{counts.get('MEDIUM',0)}</div><div class="l">MEDIUM</div></div>
  <div class="stat"><div class="n" style="color:{SEV_COLOR['LOW']}">{counts.get('LOW',0)}</div><div class="l">LOW</div></div>
  <div class="stat"><div class="n" style="color:#a78bfa">{len(self.findings)}</div><div class="l">TOTAL</div></div>
  <div class="stat"><div class="n" style="color:#22c55e">{len(self.js_files)}</div><div class="l">JS FILES</div></div>
</div>

{"<div class='banner'>⚠️ CRITICAL secrets detected — immediate action required!</div>" if counts.get('CRITICAL',0) > 0 else ""}

<div class="section">
  <h2>Findings ({len(self.findings)})</h2>
  <table>
    <thead><tr><th style="width:90px">Severity</th><th style="width:160px">Type</th><th>Value / Decoded</th><th style="width:160px">Source</th></tr></thead>
    <tbody>
      {rows if rows else '<tr><td colspan="4" style="text-align:center;color:#22c55e;padding:20px">✅ No secrets detected</td></tr>'}
    </tbody>
  </table>
</div>

<div class="section">
  <h2>JS Files Scanned ({len(self.js_files)})</h2>
  <ul>{js_list}</ul>
</div>

<p style="color:#374151;font-size:11px;margin-top:16px">
  Generated by js-secret-hunter v3 | For authorized penetration testing only
</p>
</body></html>"""

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Report saved: {filename}")
