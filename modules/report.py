#!/usr/bin/env python3
"""Report v2 - Detailed HTML with severity, snippets, remediation"""
from datetime import datetime

SEV_COLOR = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#facc15","LOW":"#94a3b8"}
SEV_BG    = {"CRITICAL":"#2d0a0a","HIGH":"#2d1500","MEDIUM":"#2d2500","LOW":"#1a1a2e"}

REMEDIATION = {
    "AWS Access Key ID":     "Rotate immediately via AWS IAM. Enable AWS CloudTrail.",
    "GitHub PAT Classic":    "Revoke at github.com/settings/tokens. Use short-lived tokens.",
    "Stripe Secret Key":     "Rotate at dashboard.stripe.com. Never expose sk_live in frontend.",
    "JWT Token":             "Check expiry/signature. Use HttpOnly cookies instead.",
    "DB Connection String":  "Move to server-side env vars. Use secrets manager.",
    "Private Key PEM":       "Replace key pair immediately. Check for unauthorized usage.",
    "Hardcoded Password":    "Move to environment variables. Use secrets vault.",
    "Hardcoded Secret":      "Move to environment variables. Use .env + server-side config.",
    "Firebase URL":          "Check Firebase security rules. Restrict access by auth.",
    "Slack Bot Token":       "Revoke at api.slack.com/apps. Regenerate token.",
    "SendGrid API Key":      "Rotate at app.sendgrid.com/settings/api_keys.",
    "Google API Key":        "Restrict key to specific APIs/IPs in Google Cloud Console.",
    "Sentry DSN":            "Rotate DSN. Restrict Sentry project access.",
    "Internal IP Exposed":   "Remove internal IPs from frontend JS. Use API proxying.",
}

class SecretReport:
    def __init__(self, target, js_files, findings):
        self.target = target
        self.js_files = js_files
        self.findings = findings

    def _severity_counts(self):
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in self.findings:
            counts[f.get("severity","LOW")] = counts.get(f.get("severity","LOW"),0) + 1
        return counts

    def save(self, filename):
        counts = self._severity_counts()

        rows = ""
        for i, f in enumerate(self.findings):
            sev = f.get("severity","LOW")
            color = SEV_COLOR.get(sev,"#888")
            bg = SEV_BG.get(sev,"#111")
            decoded_html = ""
            if f.get("decoded"):
                decoded_html = f"<div class='decoded'>🔓 {f['decoded'][:200]}</div>"
            snippet_html = ""
            if f.get("snippet"):
                snippet_html = f"<div class='snippet'>{f['snippet'][:120]}</div>"
            remediation = REMEDIATION.get(f["type"], "Review and rotate if sensitive.")
            rows += f"""
            <tr style="background:{bg}">
              <td><span class="badge" style="background:{color}">{sev}</span></td>
              <td><b>{f['type']}</b></td>
              <td class="val-cell">
                <code>{f['value'][:100]}</code>
                {decoded_html}
                {snippet_html}
              </td>
              <td><small>{f.get('source','')}</small><br><small style="color:#555">L{f.get('line','?')}</small></td>
              <td><small style="color:#94a3b8">{remediation}</small></td>
            </tr>"""

        js_list = "".join(
            f"<li><code>{url[:90]}</code> <span style='color:#555'>({len(c):,}b)</span></li>"
            for url, c in list(self.js_files.items())[:40]
        )

        risk = "CRITICAL" if counts["CRITICAL"] > 0 else \
               "HIGH" if counts["HIGH"] > 0 else \
               "MEDIUM" if counts["MEDIUM"] > 0 else \
               "CLEAN" if sum(counts.values()) == 0 else "LOW"

        risk_color = SEV_COLOR.get(risk, "#22c55e") if risk != "CLEAN" else "#22c55e"

        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>JS Secret Hunter v3 — {self.target}</title>
<style>
* {{box-sizing:border-box; margin:0; padding:0}}
body {{font-family:'Segoe UI',Arial,sans-serif; background:#0a0a12; color:#e2e0ff; padding:24px; font-size:14px}}
h1 {{color:#a78bfa; font-size:1.6em; margin-bottom:4px}}
h2 {{color:#c4b5fd; font-size:1.1em; margin:20px 0 8px}}
.meta {{color:#555; font-size:12px; margin-bottom:16px}}
.risk-banner {{background:#1e1b2e; border:2px solid {risk_color}; border-radius:10px; padding:16px 24px; margin:16px 0; display:flex; align-items:center; gap:20px}}
.risk-level {{font-size:2em; font-weight:bold; color:{risk_color}}}
.stats {{display:flex; gap:10px; margin:16px 0; flex-wrap:wrap}}
.stat {{background:#13132a; border-radius:8px; padding:12px 18px; text-align:center; border:1px solid #1e1e3a; min-width:80px}}
.stat .n {{font-size:1.8em; font-weight:bold}}
table {{width:100%; border-collapse:collapse; margin:8px 0; font-size:13px}}
td,th {{padding:8px 10px; border:1px solid #1a1a2e; vertical-align:top}}
th {{background:#16133a; color:#a5b4fc; text-align:left}}
.badge {{display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:bold; color:#fff}}
code {{color:#a78bfa; font-size:12px; word-break:break-all; background:#111; padding:2px 5px; border-radius:3px}}
.decoded {{color:#34d399; font-size:12px; margin-top:4px; padding:3px 6px; background:#052e16; border-radius:3px}}
.snippet {{color:#64748b; font-size:11px; margin-top:3px; font-style:italic}}
.val-cell {{max-width:400px}}
ul {{background:#0d0d1a; border-radius:6px; padding:10px 20px; max-height:200px; overflow-y:auto}}
li {{font-size:11px; color:#4a4a6a; padding:1px 0}}
.footer {{margin-top:24px; color:#333; font-size:11px; text-align:center}}
</style></head><body>

<h1>🔍 JS Secret Hunter <span style="color:#555;font-size:0.7em">v3</span></h1>
<p class="meta">Target: <b style="color:#c4b5fd">{self.target}</b> | Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | For authorized penetration testing only</p>

<div class="risk-banner">
  <div>
    <div style="color:#888;font-size:11px">OVERALL RISK</div>
    <div class="risk-level">{risk}</div>
  </div>
  <div style="flex:1">
    <div style="color:#aaa">JS files scanned: <b>{len(self.js_files)}</b></div>
    <div style="color:#aaa">Total findings: <b>{len(self.findings)}</b></div>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="n" style="color:#ef4444">{counts['CRITICAL']}</div><div style="color:#888">CRITICAL</div></div>
  <div class="stat"><div class="n" style="color:#f97316">{counts['HIGH']}</div><div style="color:#888">HIGH</div></div>
  <div class="stat"><div class="n" style="color:#facc15">{counts['MEDIUM']}</div><div style="color:#888">MEDIUM</div></div>
  <div class="stat"><div class="n" style="color:#94a3b8">{counts['LOW']}</div><div style="color:#888">LOW</div></div>
  <div class="stat"><div class="n" style="color:#a78bfa">{len(self.js_files)}</div><div style="color:#888">JS FILES</div></div>
</div>

<h2>Findings</h2>
{'<p style="color:#22c55e;padding:16px;background:#052e16;border-radius:8px">✅ No secrets detected. JS appears clean.</p>' if not self.findings else f'<table><tr><th>Severity</th><th>Type</th><th>Value / Decoded / Context</th><th>File</th><th>Remediation</th></tr>{rows}</table>'}

<h2>JS Files Scanned ({len(self.js_files)})</h2>
<ul>{js_list}</ul>

<p class="footer">Generated by js-secret-hunter v3 — For authorized security assessments only</p>
</body></html>"""

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Report saved: {filename}")
