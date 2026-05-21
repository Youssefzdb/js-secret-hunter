#!/usr/bin/env python3
import json

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"
BOLD="\033[1m"; RST="\033[0m"; O="\033[38;5;208m"

class Reporter:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, msg):    print(f"{B}[*]{RST} {msg}")
    def success(self, msg): print(f"{G}[+]{RST} {msg}")
    def warning(self, msg): print(f"{Y}[!]{RST} {msg}")
    def debug(self, msg):
        if self.verbose: print(f"{DIM}[~] {msg}{RST}")
    def step(self, num, msg): print(f"\n{BOLD}{C}[STEP {num}]{RST} {msg}")
    def decode(self, msg): print(f"  {G}{msg}{RST}")

    def found(self, name, sev, url, line):
        icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}
        colors = {"CRITICAL":R,"HIGH":O,"MEDIUM":Y,"LOW":B}
        icon  = icons.get(sev,"🔵")
        color = colors.get(sev,B)
        print(f"  {icon} {color}{BOLD}{name}{RST} {DIM}→ {url.split('/')[-1][:50]}:line {line}{RST}")

    def print_report(self, findings):
        crits  = [f for f in findings if f.get("severity")=="CRITICAL"]
        highs  = [f for f in findings if f.get("severity")=="HIGH"]
        meds   = [f for f in findings if f.get("severity") in ("MEDIUM","LOW")]

        print(f"\n{'═'*70}")
        print(f"{BOLD}{W}{'':^10}FINDINGS REPORT{'':^10}{RST}")
        print(f"{'═'*70}")

        def print_group(items, color, label, icon):
            if not items: return
            print(f"\n{color}{BOLD}{icon} {label} ({len(items)} findings){RST}")
            print(f"{DIM}{'─'*60}{RST}")
            for f in items:
                print(f"  {BOLD}Type:{RST}     {f.get('type','?')}")
                print(f"  {BOLD}File:{RST}     {str(f.get('url',''))[:80]}")
                print(f"  {BOLD}Line:{RST}     {f.get('line','?')}")
                print(f"  {BOLD}Value:{RST}    {Y}{str(f.get('value',''))[:100]}{RST}")
                decoded = f.get('decoded')
                if decoded:
                    print(f"  {BOLD}Decoded:{RST}  {G}{str(decoded)[:150]}{RST}")
                snippet = f.get('snippet','')
                if snippet:
                    print(f"  {BOLD}Snippet:{RST}  {DIM}{str(snippet)[:120]}{RST}")
                print()

        print_group(crits, R, "CRITICAL", "🔴")
        print_group(highs, O, "HIGH",     "🟠")
        print_group(meds,  Y, "MEDIUM/LOW","🟡")

        print(f"{'═'*70}")
        print(f"{BOLD}  SUMMARY:{RST}")
        print(f"  {R}CRITICAL : {len(crits)}{RST}")
        print(f"  {O}HIGH     : {len(highs)}{RST}")
        print(f"  {Y}MEDIUM/LOW: {len(meds)}{RST}")
        print(f"  {W}TOTAL    : {len(findings)}{RST}")
        print(f"{'═'*70}\n")

        if not findings:
            print(f"{G}[✓] No secrets found. Target may be clean.{RST}\n")

    def save_json(self, findings, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, default=str)
