import argparse
import json
from rich.console import Console
from rich.panel import Panel

from scanner.orchestrator import ScanOrchestrator
from ai.analyzer import analyze
from reports.report_generator import generate_report

console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="autosec",
        description="AutoSec AI – AI-assisted baseline security scanner"
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Domain or IP to scan")
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (no report file)"
    )
    scan_parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis step"
    )

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return

    if not args.json:
        console.print(Panel.fit(
            f"[bold cyan]AutoSec AI[/bold cyan]\nTarget: [bold]{args.target}[/bold]",
            title="Security Scan",
            border_style="cyan"
        ))

    # --------------------
    # RUN SCANNERS
    # --------------------
    orchestrator = ScanOrchestrator(args.target)
    scan_findings = orchestrator.run()

    # --------------------
    # AI ANALYSIS (OPTIONAL)
    # --------------------
    analysis = None
    if not args.no_ai:
        try:
            analysis = analyze(scan_findings)
        except Exception as e:
            analysis = {
                "risk_level": "Unknown",
                "summary": "AI analysis could not be completed.",
                "recommendation": "Review technical findings manually."
            }

    # --------------------
    # JSON OUTPUT MODE
    # --------------------
    if args.json:
        output = {
            "target": args.target,
            "findings": scan_findings,
            "analysis": analysis,
        }
        print(json.dumps(output, indent=2))
        return

    # --------------------
    # REPORT GENERATION
    # --------------------
    console.print("[yellow][+] Generating report...[/yellow]")
    report_path = generate_report(
        args.target,
        analysis,
        scan_findings
    )

    console.print(f"[bold green][✔] Scan completed successfully![/bold green]")
    console.print(f"[bold green][✔] Report saved at {report_path}[/bold green]")
