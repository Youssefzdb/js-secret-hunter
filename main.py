#!/usr/bin/env python3
"""
js-secret-hunter - JavaScript Secret & Credential Scanner
Extracts and analyzes JS files from web targets during authorized pentests
"""
import argparse
import sys
from modules.env_check import EnvironmentChecker
from modules.js_extractor import JSExtractor
from modules.secret_scanner import SecretScanner
from modules.decoder import Decoder
from modules.report import SecretReport

def main():
    parser = argparse.ArgumentParser(description="JS Secret Hunter - Authorized Pentest Only")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--output", default="js_secrets_report.html")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth for JS discovery")
    parser.add_argument("--scope", help="Allowed scope (e.g. 192.168.0.0/24 or example.com)")
    args = parser.parse_args()

    # ========== ENVIRONMENT CHECK ==========
    checker = EnvironmentChecker(args.url, args.scope)
    if not checker.validate():
        print("[!] Target outside authorized scope. Exiting.")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  JS Secret Hunter | Target: {args.url}")
    print(f"  FOR AUTHORIZED PENETRATION TESTING ONLY")
    print(f"{'='*55}\n")

    # Step 1: Extract JS files
    extractor = JSExtractor(args.url, args.depth)
    js_files = extractor.extract()
    print(f"\n[+] Found {len(js_files)} JS files\n")

    # Step 2: Scan for secrets
    scanner = SecretScanner(js_files)
    raw_findings = scanner.scan()

    # Step 3: Decode obfuscated values
    decoder = Decoder()
    findings = decoder.process(raw_findings)

    # Step 4: Report
    report = SecretReport(args.url, js_files, findings)
    report.save(args.output)
    print(f"\n[+] {len(findings)} secrets found. Report: {args.output}")

if __name__ == "__main__":
    main()
