#!/usr/bin/env python3
"""Report v3 — Full HTML with remediation, entropy, severity scoring"""
from datetime import datetime

SEV_COLOR = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#64748b"}
SEV_BG    = {"CRITICAL":"#2d0000","HIGH":"#2d1200","MEDIUM":"#1a1500","LOW":"#0f0f1a"}

REMEDIATION = {
    "AWS Access Key ID":       "🔴 Rotate immediately via AWS IAM Console. Enable CloudTrail audit logging.",
    "AWS Secret Access Key":   "🔴 Rotate immediately. Check IAM activity log for unauthorized usage.",
    "GCP API Key":             "🔴 Restrict key in GCP Console to specific APIs/IPs. Rotate immediately.",
    "Firebase Config Block":   "🔴 Secure Firebase rules. Restrict DB access to authenticated users only.",
    "Stripe Secret Key":       "🔴 Rotate at dashboard.stripe.com. Never expose sk_live in frontend code.",
    "Stripe Webhook Secret":   "🔴 Rotate webhook secret in Stripe dashboard.",
    "GitHub PAT Classic":      "🔴 Revoke at github.com/settings/tokens immediately.",
    "GitHub Fine-Grained PAT": "🔴 Revoke at github.com/settings/tokens immediately.",
    "GitLab Token":            "🔴 Revoke at gitlab.com/-/profile/personal_access_tokens.",
    "SendGrid API Key":        "🔴 Rotate at app.sendgrid.com/settings/api_keys.",
    "Slack Bot Token":         "🔴 Revoke at api.slack.com/apps. Generate new token.",
    "Twilio Account SID":      "🟠 Verify if paired with auth token. Rotate both in Twilio Console.",
    "Discord Bot Token":       "🔴 Regenerate token in Discord Developer Portal immediately.",
    "Telegram Bot Token":      "🔴 Revoke via @BotFather: /revoke",
    "MongoDB URI":             "🔴 Rotate credentials. Move to server-side env vars. Use secrets manager.",
    "PostgreSQL URI":          "🔴 Rotate credentials. Move to server-side env vars.",
    "MySQL URI":               "🔴 Rotate credentials. Move to server-side env vars.",
    "JWT Token":               "🟠 Check expiry. Verify not a long-lived token. Use HttpOnly cookies.",
    "Private Key PEM":         "🔴 Replace key pair immediately. Audit for unauthorized usage.",
    "SSH Private Key":         "🔴 Replace key pair immediately. Audit SSH access logs.",
    "Hardcoded Password":      "🟠 Move to environment variables or a secrets vault (e.g., Vault, AWS Secrets Manager).",
    "Hardcoded API Key":       "🟠 Move to server-side configuration. Never expose in frontend JS.",
    "Hardcoded Secret":        "🟠 Move to server-side configuration or secrets manager.",
    "Internal IP Exposed":     "🟡 Remove internal IPs from frontend JS. Use relative paths or API proxying.",
    "Admin Endpoint":          "🟡 Ensure admin routes are protected by auth middleware.",
    "S3 Bucket Exposed":       "🟡 Check bucket ACL/policy. Ensure no public write access.",
    "Sensitive Comment":       "ℹ️ Review comment. Remove before production deployment.",
}

class SecretReport:
    def __init__(self, target, js_files, findings):
        self.target = target
        self.js_files = js_files
        self.findings = findings

    def _counts(self):
        c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in self.findings:
            s = f.get("severity","LOW")
            c[s] = c.get(s,0) + 1
        return c

    def save(self, filename="report.html"):
        counts = self._counts()
        risk = next((s for s in ["CRITICAL","HIGH","MEDIUM","LOW"] if counts[s]>0), "CLEAN")
        risk_color = SEV_COLOR.get(risk,"#22c55e") if risk != "CLEAN" else "#22c55e"

        rows = ""
        for f in self.findings:
            sev = f.get("severity","LOW")
            c = SEV_COLOR.get(sev,"#888")
            bg = SEV_BG.get(sev,"#111")
            decoded = f'<div style="color:#34d399;font-size:11px;margin-top:4px;padding:2px 5px;background:#052e16;border-radius:3px">🔓 {f["decoded"][:200]}</div>' if f.get("decoded") else ""
            snippet = f'<div style="color:#475569;font-size:11px;font-style:italic;margin-top:3px">{f.get("snippet","")[:120]}</div>' if f.get("snippet") else ""
            rem = REMEDIATION.get(f["type"], "Review and rotate if sensitive.")
            ent = f.get("entropy","?")
            rows += f"""<tr style="background:{bg}">
              <td><span style="background:{c};color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:bold">{sev}</span></td>
              <td style="font-weight:bold;color:#c4b5fd">{f["type"]}</td>
              <td style="max-width:380px">
                <code style="color:#a78bfa;font-size:11px;word-break:break-all;background:#0d0d1a;padding:2px 4px;border-radius:3px">{f["value"][:100]}</code>
                {decoded}{snippet}
              </td>
              <td style="font-size:11px;color:#64748b">{f.get("source","")}<br>Line {f.get("line","?")} | ent={ent}</td>
              <td style="font-size:11px;color:#94a3b8">{rem}</td>
            </tr>"""

        js_rows = "".join(
            f'<li style="font-size:11px;color:#3a3a5a;padding:1px 0"><code style="color:#4a4a7a">{url[:90]}</code> <span style="color:#2a2a4a">({len(c):,}b)</span></li>'
            for url,c in list(self.js_files.items())[:50]
        )

        html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<title>JS Secret Hunter v3 | {self.target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#070711;color:#e2e0ff;padding:28px;font-size:13px;line-height:1.5}}
h1{{color:#a78bfa;font-size:1.5em;margin-bottom:2px}}
h2{{color:#7c6fcd;font-size:1em;margin:22px 0 8px;border-bottom:1px solid #1a1a2e;padding-bottom:4px}}
.meta{{color:#3a3a5a;font-size:11px;margin-bottom:18px}}
.banner{{border:2px solid {risk_color};border-radius:10px;background:#0d0d1a;padding:16px 24px;margin:14px 0;display:flex;align-items:center;gap:24px}}
.risk{{font-size:2.2em;font-weight:900;color:{risk_color}}}
.stats{{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}}
.stat{{background:#0d0d1a;border:1px solid #1a1a2e;border-radius:8px;padding:10px 18px;text-align:center;min-width:70px}}
.stat .n{{font-size:1.8em;font-weight:bold}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
td,th{{padding:7px 9px;border:1px solid #111128;vertical-align:top}}
th{{background:#0d0d20;color:#7c6fcd;font-size:11px;text-transform:uppercase}}
ul{{background:#0a0a15;border-radius:6px;padding:8px 18px;max-height:180px;overflow-y:auto;margin-top:4px}}
.clean{{background:#052e16;border:1px solid #166534;border-radius:8px;padding:14px 20px;color:#22c55e}}
.footer{{margin-top:28px;color:#1e1e3a;font-size:10px;text-align:center}}
</style></head><body>
<h1>🔍 JS Secret Hunter <small style="color:#333;font-size:0.6em">v3</small></h1>
<p class="meta">Target: <b style="color:#a78bfa">{self.target}</b> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; ⚠️ Authorized penetration testing only</p>

<div class="banner">
  <div><div style="color:#444;font-size:10px;text-transform:uppercase">Risk Level</div><div class="risk">{risk}</div></div>
  <div>
    <div style="color:#555">JS files analyzed: <b style="color:#a78bfa">{len(self.js_files)}</b></div>
    <div style="color:#555">Total findings: <b style="color:#a78bfa">{len(self.findings)}</b></div>
  </div>
</div>

<div class="stats">
  {''.join(f'<div class="stat"><div class="n" style="color:{SEV_COLOR[s]}">{counts[s]}</div><div style="color:#333;font-size:10px">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
  <div class="stat"><div class="n" style="color:#a78bfa">{len(self.js_files)}</div><div style="color:#333;font-size:10px">JS FILES</div></div>
</div>

<h2>Findings</h2>
{'<div class="clean">✅ No secrets detected — JavaScript appears clean.</div>' if not self.findings else
f'<table><tr><th>Severity</th><th>Type</th><th>Value / Decoded</th><th>File / Line</th><th>Remediation</th></tr>{rows}</table>'}

<h2>JS Sources Analyzed ({len(self.js_files)})</h2>
<ul>{js_rows}</ul>

<p class="footer">Generated by js-secret-hunter v3 · For authorized security assessments only</p>
</body></html>"""
        with open(filename,"w",encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Report: {filename}")
