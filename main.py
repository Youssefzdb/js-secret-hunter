#!/usr/bin/env python3
"""
js-secret-hunter v3 - Deep JS Secret & Credential Scanner
Authorized penetration testing only
"""
import argparse, sys
from modules.env_check import EnvironmentChecker
from modules.js_extractor import JSExtractor
from modules.secret_scanner import SecretScanner
from modules.decoder import Decoder
from modules.report import SecretReport

BANNER = r"""
     ██╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
     ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
     ██║███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██   ██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚█████╔╝███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚════╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝  v3
"""

def main():
    parser = argparse.ArgumentParser(
        description="js-secret-hunter v3 — Deep JS Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--scope",  help="Authorized scope (CIDR or domain)")
    parser.add_argument("--depth",  type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--output", default="js_secrets_report.html")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    # Environment check
    checker = EnvironmentChecker(args.url, args.scope)
    if not checker.validate():
        print("[!] Blocked: target not in authorized scope.")
        sys.exit(1)

    print(f"{'='*60}")
    print(f"  Target : {args.url}")
    print(f"  Depth  : {args.depth}")
    print(f"  Output : {args.output}")
    print(f"{'='*60}\n")

    # Step 1: Extract JS
    extractor = JSExtractor(args.url, args.depth)
    js_files = extractor.extract()

    if not js_files:
        print("[-] No JS files found.")
        sys.exit(0)

    # Step 2: Scan secrets
    scanner = SecretScanner(js_files)
    raw = scanner.scan()

    # Step 3: Decode
    decoder = Decoder()
    findings = decoder.process(raw)

    # Step 4: Summary
    print(f"\n{'='*60}")
    from collections import Counter
    sev_counts = Counter(f["severity"] for f in findings)
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        n = sev_counts.get(sev, 0)
        if n: print(f"  {sev:8}: {n}")
    print(f"  {'TOTAL':8}: {len(findings)}")
    print(f"{'='*60}")

    # Step 5: Report
    report = SecretReport(args.url, js_files, findings)
    report.save(args.output)

if __name__ == "__main__":
    main()
