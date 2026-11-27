#!/usr/bin/env python3
# cli.py
# Command-line interface for the Cryptographic Protocol Analyzer.
#
# Usage:
#   python cli.py --file path/to/capture.pcap
#   python cli.py --demo

import argparse
import sys
import os

from analyzer import analyze_pcap, run_demo_analysis
from report_generator import findings_to_dataframe, compute_summary, save_csv_report
from rules import SEVERITY_COLORS

# ---- ANSI color codes for terminal output ----
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREY   = "\033[90m"

SEVERITY_ANSI = {
    "Critical": RED,
    "High":     ORANGE,
    "Medium":   YELLOW,
    "Low":      GREEN,
    "Info":     BLUE,
}

BANNER_UNICODE = f"""{CYAN}
╔══════════════════════════════════════════════════════════╗
║      Cryptographic Protocol Analyzer  v1.0               ║
║      Computer Security Course Project                    ║
║      For authorized and educational use only             ║
╚══════════════════════════════════════════════════════════╝
{RESET}"""

BANNER_ASCII = f"""{CYAN}
+----------------------------------------------------------+
|      Cryptographic Protocol Analyzer  v1.0               |
|      Computer Security Course Project                    |
|      For authorized and educational use only             |
+----------------------------------------------------------+
{RESET}"""

STDOUT_ENCODING = (getattr(sys.stdout, "encoding", None) or "").lower()
UTF_OUTPUT = "utf" in STDOUT_ENCODING
HLINE = "─" if UTF_OUTPUT else "-"


def print_banner():
    # Some Windows terminals default to encodings that cannot print box-drawing chars.
    banner = BANNER_UNICODE if UTF_OUTPUT else BANNER_ASCII
    print(banner)


def severity_color(sev: str) -> str:
    return SEVERITY_ANSI.get(sev, RESET)


def print_summary(summary: dict):
    print(f"\n{BOLD}{HLINE*60}{RESET}")
    print(f"{BOLD}  ANALYSIS SUMMARY{RESET}")
    print(f"{HLINE*60}")
    print(f"  Analyzed at    : {summary['analyzed_at']}")
    print(f"  Source         : {summary['source'].upper()}")
    print(f"  Total Packets  : {summary['total_packets']:,}")
    print(f"  Total Findings : {BOLD}{summary['total_findings']}{RESET}")
    print()
    print(f"  {RED}Critical : {summary['critical']}{RESET}")
    print(f"  {ORANGE}High     : {summary['high']}{RESET}")
    print(f"  {YELLOW}Medium   : {summary['medium']}{RESET}")
    print(f"  {GREEN}Low      : {summary['low']}{RESET}")
    print(f"{HLINE*60}\n")


def print_findings(findings: list):
    if not findings:
        print(f"{GREEN}  No insecure protocols detected.{RESET}\n")
        return

    for i, f in enumerate(findings, start=1):
        sev   = f.get("severity", "Low")
        color = severity_color(sev)
        print(f"{color}{BOLD}[{i:02d}] [{sev.upper()}] {f.get('issue', '')}{RESET}")
        print(f"     Protocol    : {f.get('protocol', 'N/A')}")
        print(f"     Source      : {f.get('src_ip', 'N/A')}:{f.get('src_port', '')}")
        print(f"     Destination : {f.get('dst_ip', 'N/A')}:{f.get('dst_port', '')}")
        print(f"     Transport   : {f.get('transport', 'TCP')}")
        print(f"     Why Insecure: {GREY}{f.get('explanation', '')}{RESET}")
        print(f"     Fix         : {CYAN}{f.get('recommendation', '')}{RESET}")
        print()


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Cryptographic Protocol Analyzer — detect insecure protocols in pcap files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--file", "-f",
        metavar="PATH",
        help="Path to a .pcap or .pcapng file to analyze.",
    )
    group.add_argument(
        "--demo", "-d",
        action="store_true",
        help="Run a demo analysis using the built-in sample dataset.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save a CSV report to the reports/ directory.",
    )

    args = parser.parse_args()

    # ---- Run analysis ----
    if args.demo:
        print(f"{CYAN}[*] Running demo analysis with built-in dataset...{RESET}\n")
        result = run_demo_analysis()
    else:
        path = os.path.abspath(args.file)
        print(f"{CYAN}[*] Analyzing file: {path}{RESET}\n")
        result = analyze_pcap(path)

    # ---- Handle errors ----
    if result.get("error"):
        print(f"{RED}[ERROR] {result['error']}{RESET}")
        sys.exit(1)

    # ---- Print results ----
    summary = compute_summary(result)
    print_summary(summary)
    print_findings(result["findings"])

    # ---- Save CSV ----
    if not args.no_save:
        label = "demo" if args.demo else "pcap"
        csv_path = save_csv_report(result, label=label)
        print(f"{GREEN}[+] CSV report saved to: {csv_path}{RESET}\n")
    else:
        print(f"{GREY}[i] CSV report not saved (--no-save flag set).{RESET}\n")


if __name__ == "__main__":
    main()
