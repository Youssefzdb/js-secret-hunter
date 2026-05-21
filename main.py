#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║       JS Secret Hunter v2.0 — Shadow Core             ║
║  Crawl JS · Find Secrets · Decode/Decrypt             ║
╚═══════════════════════════════════════════════════════╝
Usage:
  python3 main.py https://target.com
  python3 main.py https://target.com --output report.json -v
  python3 main.py https://target.com --no-decode

For authorized testing ONLY.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
from modules.crawler   import JSCrawler
from modules.extractor import SecretExtractor
from modules.decoder   import SecretDecoder
from utils.reporter    import Reporter

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; DIM="\033[2m"; BOLD="\033[1m"; RST="\033[0m"

BANNER = f"""
{R}
   ██╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
   ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ██║███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██ ██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚█████╔╝███████║  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚════╝ ╚══════╝  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RST}{DIM}  Red Team JS Secret Hunter v2.0 — Shadow Core | Authorized use only{RST}
"""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='JS Secret Hunter — Extract & decode secrets from JavaScript files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py https://target.com
  python3 main.py https://target.com --output report.json
  python3 main.py https://target.com --depth 2 --verbose
        """
    )
    parser.add_argument('url',
        help='Target URL to scan (e.g. https://example.com)')
    parser.add_argument('--depth', type=int, default=1,
        help='Crawl depth: 1=single page, 2=follow links (default: 1)')
    parser.add_argument('--timeout', type=int, default=12,
        help='HTTP request timeout in seconds (default: 12)')
    parser.add_argument('--output',
        help='Save full report as JSON to this file')
    parser.add_argument('--no-decode', action='store_true',
        help='Skip decode/decrypt attempts (faster)')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Show all JS files and debug info')
    args = parser.parse_args()

    target = args.url
    if not target.startswith('http'):
        target = 'https://' + target

    reporter = Reporter(args.verbose)
    reporter.info(f"Target  : {W}{target}{RST}")
    reporter.info(f"Mode    : {'Deep crawl (depth=' + str(args.depth) + ')' if args.depth > 1 else 'Single page'}")
    reporter.info(f"Decode  : {'Enabled' if not args.no_decode else 'Disabled'}")

    # ── STEP 1: Crawl ─────────────────────────────────────────
    reporter.step("1", "Crawling target for JavaScript files...")
    crawler  = JSCrawler(target, args.depth, args.timeout, reporter)
    js_files = crawler.run()

    if not js_files:
        reporter.warning("No JavaScript files found.")
        reporter.info("Try adding --depth 2 to crawl subpages, or check if the site uses SPA lazy loading.")
        sys.exit(0)

    reporter.success(f"Collected {len(js_files)} JS source(s)")

    # ── STEP 2: Extract Secrets ───────────────────────────────
    reporter.step("2", "Scanning for secrets (API keys, tokens, passwords, private keys...)")
    extractor    = SecretExtractor(reporter)
    all_findings = []

    for src_url, content in js_files.items():
        label = src_url if src_url.startswith('[INLINE') else src_url.split('/')[-1][:60]
        reporter.info(f"Scanning: {label}")
        findings = extractor.scan(src_url, content)
        all_findings.extend(findings)

    reporter.success(f"Total findings: {len(all_findings)}")

    # ── STEP 3: Decode / Decrypt ──────────────────────────────
    if not args.no_decode and all_findings:
        reporter.step("3", "Attempting to decode/decrypt suspicious values...")
        decoder = SecretDecoder(reporter)
        decoded_count = 0
        for finding in all_findings:
            result = decoder.decode(finding['value'])
            if result:
                finding['decoded'] = result
                decoded_count += 1
        reporter.success(f"Successfully decoded {decoded_count} value(s)")

    # ── STEP 4: Report ────────────────────────────────────────
    reporter.step("4", "Generating report...")
    reporter.print_report(all_findings)

    if args.output:
        reporter.save_json(all_findings, args.output)
        reporter.success(f"Report saved → {args.output}")


if __name__ == '__main__':
    main()
