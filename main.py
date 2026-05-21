#!/usr/bin/env python3
"""
js-secret-hunter v3
Deep JS analysis tool for authorized web application pentests
"""
import argparse, sys
from modules.env_check import EnvironmentChecker
from modules.js_extractor import JSExtractor
from modules.secret_scanner import SecretScanner
from modules.decoder import Decoder
from modules.report import SecretReport

def main():
    parser = argparse.ArgumentParser(
        description="JS Secret Hunter v3 — Authorized Pentest Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url http://192.168.1.100            # Lab target (auto-allowed)
  python main.py --url http://10.10.10.50              # HTB/CTF target
  python main.py --url https://target.com --scope target.com  # Authorized external
  python main.py --url https://target.com --depth 4 --output pentest.html
        """
    )
    parser.add_argument("--url",    required=True,  help="Target URL")
    parser.add_argument("--scope",  default=None,   help="Authorized scope (domain or CIDR)")
    parser.add_argument("--depth",  type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("--output", default="js_secrets_report.html", help="Output report file")
    parser.add_argument("--no-env-check", action="store_true", help="Skip environment check (use with --scope)")
    args = parser.parse_args()

    # ── Environment Check ─────────────────────────────────────────────
    if not args.no_env_check:
        checker = EnvironmentChecker(args.url, args.scope)
        if not checker.validate():
            print("\n[!] Environment check failed. Use --scope to define authorized target.")
            sys.exit(1)

    print(f"\n{'═'*60}")
    print(f"  JS Secret Hunter v3")
    print(f"  Target : {args.url}")
    print(f"  Depth  : {args.depth}")
    print(f"  Output : {args.output}")
    print(f"  ⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY")
    print(f"{'═'*60}\n")

    # ── Step 1: Extract JS ────────────────────────────────────────────
    extractor = JSExtractor(args.url, depth=args.depth)
    js_files = extractor.extract()

    if not js_files:
        print("[!] No JS files found. Check target URL.")
        sys.exit(1)

    # ── Step 2: Scan secrets ──────────────────────────────────────────
    scanner = SecretScanner(js_files)
    findings = scanner.scan()

    # ── Step 3: Decode obfuscated values ──────────────────────────────
    decoder = Decoder()
    findings = decoder.process(findings)

    # ── Step 4: Report ────────────────────────────────────────────────
    report = SecretReport(args.url, js_files, findings)
    report.save(args.output)

    # ── Summary ───────────────────────────────────────────────────────
    sev_counts = {}
    for f in findings:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s,0) + 1

    print(f"\n{'═'*60}")
    print(f"  SUMMARY")
    print(f"  JS files analyzed : {len(js_files)}")
    for s in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        n = sev_counts.get(s,0)
        if n:
            print(f"  {s:10} : {n}")
    print(f"  Report : {args.output}")
    print(f"{'═'*60}")

if __name__ == "__main__":
    main()
