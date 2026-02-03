import argparse
from rich.console import Console
from rich.panel import Panel

from scanner.nmap_scan import run_nmap
from scanner.nikto_scan import run_nikto
from ai.analyzer import analyze
from reports.report_generator import generate_report

console = Console()

def main():
    parser = argparse.ArgumentParser(
        prog="autosec",
        description="AutoSec AI – AI-assisted security scanning tool"
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Domain or IP to scan")

    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return

    console.print(Panel.fit(
        f"[bold cyan]AutoSec AI[/bold cyan]\nTarget: [bold]{args.target}[/bold]",
        title="Security Scan",
        border_style="cyan"
    ))

    console.print("[yellow][+] Running Nmap scan...[/yellow]")
    scan_results = run_nmap(args.target)

    web_ports = [
        r for r in scan_results
        if r["state"] == "open" and r["port"] in [80, 443]
    ]

    nikto_results = None
    if web_ports:
        console.print("[yellow][+] Web service detected — running Nikto scan...[/yellow]")
        nikto_results = run_nikto(args.target)
    else:
        console.print("[cyan][-] No web ports detected, skipping Nikto[/cyan]")

    console.print("[yellow][+] Analyzing results with AI...[/yellow]")
    analysis = analyze(scan_results, nikto_results)

    console.print("[yellow][+] Generating report...[/yellow]")
    report_path = generate_report(
        args.target,
        analysis,
        scan_results,
        nikto_results
    )

    console.print(f"[bold green][✔] Scan completed successfully![/bold green]")
    console.print(f"[bold green][✔] Report saved at {report_path}[/bold green]")
