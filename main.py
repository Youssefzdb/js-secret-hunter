#!/usr/bin/env python3
"""
js-secret-hunter v4
- JS Secret Scanner + Header Analysis + API Endpoint Discovery
- For authorized penetration testing only
"""
import argparse, sys, json
from modules.env_check import EnvironmentChecker
from modules.js_extractor import JSExtractor
from modules.secret_scanner import SecretScanner
from modules.decoder import Decoder
from modules.header_analyzer import HeaderAnalyzer
from modules.endpoint_finder import EndpointFinder
from modules.report import SecretReport

def banner():
    print("""
  ╔══════════════════════════════════════════════════════╗
  ║         JS SECRET HUNTER v4                         ║
  ║  JS Secrets · Headers · Endpoints · Decoders        ║
  ║  For authorized penetration testing only            ║
  ╚══════════════════════════════════════════════════════╝
""")

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="js-secret-hunter v4 — Authorized Pentest Tool"
    )
    parser.add_argument("--url",      required=True, help="Target URL")
    parser.add_argument("--scope",    default=None,  help="Authorized scope (IP/CIDR/domain)")
    parser.add_argument("--depth",    type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--output",   default="report.html", help="Output HTML report")
    parser.add_argument("--json",     default=None,  help="Export findings as JSON")
    parser.add_argument("--probe",    action="store_true", help="Probe discovered API endpoints")
    parser.add_argument("--no-headers", action="store_true", help="Skip header analysis")
    parser.add_argument("--quiet",    action="store_true", help="Suppress verbose output")
    args = parser.parse_args()

    # ── Environment Check ──────────────────────────────────
    checker = EnvironmentChecker(args.url, args.scope)
    if not checker.validate():
        print("[!] Environment check failed. Exiting.")
        sys.exit(1)

    all_findings = []

    # ── Step 1: Header Analysis ────────────────────────────
    if not args.no_headers:
        print("\n[1/4] Header Security Analysis")
        print("─" * 50)
        ha = HeaderAnalyzer(args.url)
        header_findings = ha.analyze()
        all_findings.extend(header_findings)

    # ── Step 2: JS Extraction ──────────────────────────────
    print("\n[2/4] JavaScript Extraction")
    print("─" * 50)
    extractor = JSExtractor(args.url, depth=args.depth)
    js_files = extractor.extract()

    # ── Step 3: Secret Scanning ────────────────────────────
    print("\n[3/4] Secret & Credential Scanning")
    print("─" * 50)
    scanner = SecretScanner(js_files)
    secret_findings = scanner.scan()

    # Decode obfuscated values
    decoder = Decoder()
    secret_findings = decoder.process(secret_findings)
    all_findings.extend(secret_findings)

    # ── Step 4: Endpoint Discovery ─────────────────────────
    print("\n[4/4] API Endpoint Discovery")
    print("─" * 50)
    ef = EndpointFinder(args.url, js_files)
    endpoints, ep_findings = ef.find(probe=args.probe)
    all_findings.extend(ep_findings)

    # ── Summary ────────────────────────────────────────────
    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in all_findings:
        sev = f.get("severity","LOW")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print(f"""
  {'═'*55}
  FINAL SUMMARY
  {'═'*55}
  🔴 CRITICAL : {sev_counts['CRITICAL']}
  🟠 HIGH     : {sev_counts['HIGH']}
  🟡 MEDIUM   : {sev_counts['MEDIUM']}
  ⚪  LOW      : {sev_counts['LOW']}
  ─────────────
  TOTAL       : {len(all_findings)}
  JS FILES    : {len(js_files)}
  ENDPOINTS   : {len(endpoints)}
  {'═'*55}
""")

    # ── Reports ────────────────────────────────────────────
    report = SecretReport(args.url, js_files, all_findings, endpoints)
    report.save(args.output)

    if args.json:
        safe_findings = []
        for f in all_findings:
            sf = f.copy()
            if isinstance(sf.get("decoded"), dict):
                sf["decoded"] = sf["decoded"].get("text", "")
            safe_findings.append(sf)
        with open(args.json, "w") as jf:
            json.dump(safe_findings, jf, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved: {args.json}")

    print(f"\n[+] Done! Report: {args.output}")

if __name__ == "__main__":
    main()
