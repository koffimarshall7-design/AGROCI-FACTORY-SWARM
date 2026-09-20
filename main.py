"""Interface finale - Pentest Autonome 11-agents."""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.orchestrator import Orchestrator

console = Console()

BANNER = """
[bold red]RED[/bold red] | [cyan]WEB[/cyan] | [yellow]NETWORK[/yellow] | [magenta]STEALTH[/magenta]
[bold]EXPLOIT[/bold] | [white]CRITIC[/white] | [green]RISK[/green] | [blue]BLUE[/blue]
[bold magenta]PURPLE[/bold magenta] | [white]REPORT[/white] | [yellow]NOTIFY[/yellow]
[dim]Moteur: GPT-OSS 120B (Groq)[/dim]
"""


def show_findings(report, key):
    findings = report.get(key, {}).get("findings", [])
    if not findings:
        return
    table = Table(title=f"Findings {key.upper()}")
    table.add_column("Type", style="cyan")
    table.add_column("Severite", style="red")
    table.add_column("Detail", style="dim")
    for f in findings[:10]:
        detail = f.get("url") or f.get("header") or f.get("port") or ""
        table.add_row(
            str(f.get("type", "?")),
            str(f.get("severity", "?")),
            str(detail)[:60],
        )
    console.print(table)


def main():
    console.print(Panel(BANNER, title="Pentest Autonome 11-agents", border_style="cyan"))

    target = console.input("[bold]Cible (URL/IP/domaine): [/bold]").strip()
    if not target:
        console.print("[red]Cible vide.[/red]")
        return

    # Mode bug bounty ?
    console.print("\n[dim]Mode disponible:[/dim]")
    console.print("  [cyan]1[/cyan] - Test libre (ta responsabilite)")
    console.print("  [cyan]2[/cyan] - Bug bounty strict (verifie config/programs.json)")
    mode = console.input("Mode [1/2] (defaut=1): ").strip() or "1"

    enforce = (mode == "2")

    if not enforce:
        console.print(f"\n[dim]Cible: [cyan]{target}[/cyan][/dim]")
        console.print("[dim]En continuant tu confirmes avoir l'autorisation legale.[/dim]")
        if console.input("Confirmer ? [o/N] ").strip().lower() != "o":
            console.print("[red]Annule.[/red]")
            return

    objective = console.input("\n[bold]Objectif: [/bold]").strip() or "Audit complet de securite"

    console.print(f"\n[bold cyan]>>> Lancement...[/bold cyan]\n")
    try:
        orch = Orchestrator(scope=[target], enforce_bugbounty=enforce)
        report = orch.run(objective)
    except Exception as e:
        console.print(f"[red]Erreur: {e}[/red]")
        import traceback
        traceback.print_exc()
        return

    # Resultats
    console.print("\n" + "=" * 60)
    console.print("[bold green]RESULTAT FINAL[/bold green]")
    console.print("=" * 60)

    show_findings(report, "red")
    show_findings(report, "web")
    show_findings(report, "network")

    critic = report.get("critic", {})
    console.print(f"\n[bold]CRITIC :[/bold] "
                  f"[green]{len(critic.get('validated', []))} valides[/green] / "
                  f"[red]{len(critic.get('rejected', []))} rejetes[/red]")

    risk = report.get("risk", {})
    console.print(f"[bold]RISK :[/bold] CVSS moyen {risk.get('average_cvss', '?')} | "
                  f"Critiques {risk.get('critical_count', 0)}")

    purple = report.get("purple", {}).get("synthesis", {})
    score = purple.get("score", "?")
    console.print(f"\n[bold cyan]SCORE GLOBAL : {score}/100[/bold cyan]")

    actions = purple.get("priority_actions", [])
    if actions:
        console.print("\n[bold]Actions prioritaires :[/bold]")
        for i, a in enumerate(actions[:5], 1):
            console.print(f"  {i}. {a}")

    # Fichiers generes
    console.print(f"\n[green]JSON   : {report.get('report_path')}[/green]")
    if "report_files" in report:
        console.print(f"[green]HTML   : {report['report_files']['html']}[/green]")
        if report['report_files'].get('pdf'):
            console.print(f"[green]PDF    : {report['report_files']['pdf']}[/green]")


if __name__ == "__main__":
    main()
