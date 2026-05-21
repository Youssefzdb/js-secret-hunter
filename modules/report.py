#!/usr/bin/env python3
"""Report v4 - HTML with endpoints section + remediation + entropy scores"""
from datetime import datetime

SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"]
SEV_COLOR = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#facc15","LOW":"#94a3b8"}
SEV_BG    = {"CRITICAL":"#2a0808","HIGH":"#2a1400","MEDIUM":"#2a2200","LOW":"#16162a"}

REMEDIATION = {
    "AWS Access Key ID":        "Rotate via AWS IAM immediately. Enable CloudTrail.",
    "GCP API Key":              "Restrict key scope in Google Cloud Console.",
    "Firebase API Key":         "Add Firebase security rules. Restrict domains.",
    "Stripe Secret Key":        "Rotate at dashboard.stripe.com. Never use sk_live in frontend.",
    "GitHub PAT Classic":       "Revoke at github.com/settings/tokens.",
    "GitHub PAT Fine-Grained":  "Revoke at github.com/settings/personal-access-tokens.",
    "Slack Bot Token":          "Revoke at api.slack.com/apps.",
    "SendGrid API Key":         "Rotate at app.sendgrid.com/settings/api_keys.",
    "JWT Token":                "Check expiry/issuer. Use HttpOnly cookies for session tokens.",
    "Twilio Account SID":       "Check for unauthorized usage at console.twilio.com.",
    "MongoDB URI":              "Move to server-side env vars. Restrict DB network access.",
    "PostgreSQL URI":           "Move to server-side env vars. Use connection pooling.",
    "Private Key PEM":          "Replace key pair immediately. Check for unauthorized usage.",
    "Hardcoded Password":       "Move to environment variables. Use a secrets manager.",
    "Hardcoded Secret":         "Move to environment variables. Use .env + server-side config.",
    "Discord Bot Token":        "Regenerate at discord.com/developers.",
    "Telegram Bot Token":       "Revoke via @BotFather: /revoke command.",
    "Internal IP Exposed":      "Remove internal IPs from frontend JS. Use API proxying.",
    "Admin Path Disclosure":    "Restrict admin paths to VPN/IP allowlist.",
    "CORS Misconfiguration":    "Replace wildcard with specific allowed origins.",
    "Missing Header: Strict-Transport-Security": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "Missing Header: Content-Security-Policy":   "Implement CSP with strict directives.",
    "Missing Header: X-Content-Type-Options":    "Add: X-Content-Type-Options: nosniff",
    "Missing Header: X-Frame-Options":           "Add: X-Frame-Options: DENY",
}

class SecretReport:
    def __init__(self, target, js_files, findings, endpoints=None):
        self.target = target
        self.js_files = js_files
        self.findings = sorted(findings, key=lambda x: SEV_ORDER.index(x.get("severity","LOW")))
        self.endpoints = endpoints or []

    def _counts(self):
        c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in self.findings:
            s = f.get("severity","LOW")
            c[s] = c.get(s,0) + 1
        return c

    def save(self, filename):
        counts = self._counts()
        risk = "CLEAN" if sum(counts.values()) == 0 else \
               "CRITICAL" if counts["CRITICAL"] else \
               "HIGH" if counts["HIGH"] else \
               "MEDIUM" if counts["MEDIUM"] else "LOW"
        risk_color = {"CLEAN":"#22c55e","CRITICAL":"#ef4444","HIGH":"#f97316",
                      "MEDIUM":"#facc15","LOW":"#94a3b8"}.get(risk,"#888")

        rows = ""
        for f in self.findings:
            sev = f.get("severity","LOW")
            col = SEV_COLOR.get(sev,"#888")
            bg  = SEV_BG.get(sev,"#111")
            ent = f.get("entropy","")
            ent_html = f'<span style="color:{"#ef4444" if isinstance(ent,float) and ent>3.5 else "#555"};font-size:10px">{ent}</span>' if ent else ""
            dec = f.get("decoded")
            dec_text = dec.get("text","") if isinstance(dec,dict) else (dec or "")
            dec_html = f'<div style="color:#a78bfa;font-size:11px;margin-top:3px">🔓 {dec_text[:180]}</div>' if dec_text else ""
            snip = f.get("snippet","")[:100]
            snip_html = f'<div style="color:#475569;font-size:10px;margin-top:2px;font-style:italic">{snip}</div>' if snip else ""
            remediation = REMEDIATION.get(f["type"], "Review and rotate if sensitive.")
            rows += f"""<tr style="background:{bg}">
              <td><span style="color:{col};font-weight:bold;font-size:12px">{sev}</span></td>
              <td style="font-size:12px;white-space:nowrap">{f['type']}</td>
              <td><code style="font-size:11px;word-break:break-all;color:#a78bfa">{f['value'][:110]}</code>{dec_html}{snip_html}</td>
              <td style="font-size:11px;color:#64748b;white-space:nowrap">{f.get('source','')[:35]}</td>
              <td style="text-align:center">{ent_html}</td>
              <td style="font-size:11px;color:#7c7c9a">{remediation}</td>
            </tr>"""

        ep_rows = ""
        for ep in self.endpoints[:50]:
            methods = ", ".join(ep.get("methods",[]))
            info = ep.get("info","")
            ep_rows += f"""<tr>
              <td><code style="font-size:11px">{ep['url'][:80]}</code></td>
              <td style="font-size:12px;color:#a78bfa">{methods}</td>
              <td style="font-size:11px;color:{'#f97316' if info else '#555'}">{info or '—'}</td>
            </tr>"""

        js_list = "".join(
            f'<li><code style="color:#475569;font-size:11px">{url[:90]}</code> <span style="color:#333">({len(c):,}b)</span></li>'
            for url,c in list(self.js_files.items())[:50]
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>js-secret-hunter v4 — {self.target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#050510;color:#ddd8ff;padding:28px;font-size:14px}}
h1{{color:#a78bfa;font-size:1.5em;font-weight:700}}
h2{{color:#7c6fd4;font-size:1em;margin:20px 0 8px;text-transform:uppercase;letter-spacing:1px}}
.meta{{color:#3a3a5a;font-size:12px;margin:4px 0 16px}}
.risk{{display:inline-flex;align-items:center;gap:14px;background:#0d0d20;border:2px solid {risk_color};border-radius:10px;padding:12px 20px;margin:12px 0}}
.risk-label{{font-size:2em;font-weight:bold;color:{risk_color}}}
.stats{{display:flex;gap:8px;margin:14px 0;flex-wrap:wrap}}
.stat{{background:#0c0c1e;border:1px solid #1c1c3a;border-radius:8px;padding:10px 16px;text-align:center;min-width:75px}}
.stat .n{{font-size:1.8em;font-weight:bold;line-height:1}}
.stat .l{{font-size:10px;color:#3a3a5a;margin-top:2px}}
.card{{background:#08081a;border:1px solid #14143a;border-radius:10px;padding:16px;margin:14px 0}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{padding:7px 9px;border-bottom:1px solid #0c0c20;vertical-align:top}}
th{{background:#060618;color:#7c86d4;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}}
tr:hover td{{background:#0d0d22}}
code{{font-family:'Courier New',monospace}}
ul{{list-style:none;max-height:170px;overflow-y:auto;padding:8px 12px;background:#040410;border-radius:6px}}
li{{padding:1px 0}}
.empty{{text-align:center;color:#22c55e;padding:20px;font-size:13px}}
.footer{{margin-top:20px;text-align:center;color:#1a1a3a;font-size:11px}}
</style></head><body>

<h1>🔍 js-secret-hunter <span style="color:#3a3a6a;font-weight:400">v4</span></h1>
<p class="meta">Target: <b style="color:#a78bfa">{self.target}</b> &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;·&nbsp; Authorized penetration testing only</p>

<div class="risk">
  <div>
    <div style="color:#2a2a4a;font-size:10px;text-transform:uppercase">Risk Level</div>
    <div class="risk-label">{risk}</div>
  </div>
  <div>
    <div style="color:#666;font-size:12px">Findings: <b style="color:#ddd">{len(self.findings)}</b></div>
    <div style="color:#666;font-size:12px">JS Files: <b style="color:#ddd">{len(self.js_files)}</b></div>
    <div style="color:#666;font-size:12px">Endpoints: <b style="color:#ddd">{len(self.endpoints)}</b></div>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="n" style="color:#ef4444">{counts['CRITICAL']}</div><div class="l">CRITICAL</div></div>
  <div class="stat"><div class="n" style="color:#f97316">{counts['HIGH']}</div><div class="l">HIGH</div></div>
  <div class="stat"><div class="n" style="color:#facc15">{counts['MEDIUM']}</div><div class="l">MEDIUM</div></div>
  <div class="stat"><div class="n" style="color:#94a3b8">{counts['LOW']}</div><div class="l">LOW</div></div>
</div>

<div class="card">
  <h2>🔑 Secrets & Credentials</h2>
  <table>
    <tr><th>Sev</th><th>Type</th><th>Value / Context</th><th>File</th><th>Entropy</th><th>Remediation</th></tr>
    {''.join([rows]) if rows else '<tr><td colspan=6 class="empty">✅ No secrets detected</td></tr>'}
  </table>
</div>

{"" if not self.endpoints else f'''<div class="card">
  <h2>🌐 API Endpoints ({len(self.endpoints)} accessible)</h2>
  <table>
    <tr><th>URL</th><th>Methods</th><th>Notes</th></tr>
    {ep_rows}
  </table>
</div>'''}

<div class="card">
  <h2>📁 JS Files Scanned ({len(self.js_files)})</h2>
  <ul>{js_list}</ul>
</div>

<p class="footer">js-secret-hunter v4 — For authorized security assessments only. Unauthorized use is illegal.</p>
</body></html>"""

        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Report saved: {filename}")
