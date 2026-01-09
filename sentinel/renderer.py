"""
Report rendering. Because raw data is just numbers screaming into the void.
Transforming tactical intelligence into strategic clarity.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from sentinel.models import SecurityReport, HeaderQuality, Severity


console = Console()


def render_report(report: SecurityReport, verbose: bool = False) -> None:
    """Render comprehensive analysis report. The intelligence brief."""
    
    # Calculate adjusted score with exposure penalty
    adjusted_score = max(0, report.total_score - report.exposure_penalty)
    score_pct = (adjusted_score / report.max_score * 100) if report.max_score > 0 else 0
    
    # Determine assessment level - the verdict
    if score_pct >= 85:
        score_color = "green"
        assessment = "STRONG"
    elif score_pct >= 70:
        score_color = "yellow"
        assessment = "ADEQUATE"
    elif score_pct >= 50:
        score_color = "orange3"
        assessment = "WEAK"
    else:
        score_color = "red"
        assessment = "VULNERABLE"
    
    # Header panel - mission summary
    console.print()
    panel_content = (
        f"[bold]Target:[/bold] {report.final_url}\n"
        f"[bold]Status:[/bold] {report.status_code}\n"
        f"[bold]Score:[/bold] [{score_color}]{adjusted_score:.1f}/{report.max_score:.1f}[/{score_color}] "
        f"([{score_color}]{score_pct:.1f}%[/{score_color}])\n"
        f"[bold]Assessment:[/bold] [{score_color}]{assessment}[/{score_color}]"
    )
    
    if report.exposure_penalty > 0:
        panel_content += f"\n[bold]Exposure Penalty:[/bold] [red]-{report.exposure_penalty:.1f}[/red]"
    
    if len(report.redirect_chain) > 1:
        panel_content += f"\n[bold]Redirects:[/bold] {len(report.redirect_chain) - 1}"
    
    console.print(Panel(
        panel_content,
        title="Sentinel Analysis Report",
        border_style="cyan"
    ))
    console.print()
    
    # Warnings - tactical alerts
    if report.warnings:
        console.print(Panel(
            "\n".join(f"• {w}" for w in report.warnings),
            title="⚠️  Warnings",
            border_style="yellow",
            padding=(1, 2)
        ))
        console.print()
    
    # Security headers table - the detailed analysis
    table = Table(
        title="Security Header Analysis",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    
    table.add_column("Header", style="bold", width=32)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Quality", justify="center", width=12)
    table.add_column("Score", justify="right", width=10)
    table.add_column("Analysis", width=50)
    
    for analysis in report.analyses:
        # Skip INFO headers with no issues unless verbose
        if not verbose and analysis.expected_severity == Severity.INFO and not analysis.issues:
            continue
        
        # Status indicator
        if analysis.present:
            if analysis.quality in (HeaderQuality.EXCELLENT, HeaderQuality.GOOD):
                status = "[green]✓[/green]"
            elif analysis.quality == HeaderQuality.WEAK:
                status = "[yellow]⚠[/yellow]"
            else:
                status = "[red]✗[/red]"
        else:
            status = "[dim]○[/dim]"
        
        # Quality display
        quality_colors = {
            HeaderQuality.EXCELLENT: "green",
            HeaderQuality.GOOD: "cyan",
            HeaderQuality.WEAK: "yellow",
            HeaderQuality.DANGEROUS: "red",
            HeaderQuality.MISSING: "dim",
        }
        quality_color = quality_colors.get(analysis.quality, "white")
        quality_display = f"[{quality_color}]{analysis.quality.value.upper()}[/{quality_color}]"
        
        # Score display
        score_display = f"{analysis.score:.1f}/{analysis.max_score:.1f}"
        
        # Analysis details - issues first, then recommendations
        details_parts = []
        if analysis.issues:
            details_parts.extend(analysis.issues)
        if verbose and analysis.recommendations:
            details_parts.extend([f"→ {r}" for r in analysis.recommendations])
        if not details_parts and analysis.recommendations:
            # Non-verbose: show first recommendation if no issues
            details_parts.append(analysis.recommendations[0])
        
        details = "\n".join(details_parts) if details_parts else "—"
        
        table.add_row(
            analysis.name,
            status,
            quality_display,
            score_display,
            details
        )
    
    console.print(table)
    console.print()
    
    # Priority recommendations - critical action items
    critical_issues = [
        a for a in report.analyses
        if (not a.present and a.expected_severity in (Severity.CRITICAL, Severity.HIGH)) or
           (a.quality in (HeaderQuality.DANGEROUS, HeaderQuality.WEAK) and
            a.expected_severity in (Severity.CRITICAL, Severity.HIGH))
    ]
    
    if critical_issues:
        recommendations = []
        for analysis in critical_issues:
            if analysis.recommendations:
                rec = analysis.recommendations[0]
                recommendations.append(f"• [bold]{analysis.name}:[/bold] {rec}")
        
        if recommendations:
            console.print(Panel(
                "\n".join(recommendations),
                title="🎯 Priority Recommendations",
                border_style="red",
                padding=(1, 2)
            ))
            console.print()
    
    # Redirect chain (verbose only) - the full journey
    if verbose and len(report.redirect_chain) > 1:
        redirect_table = Table(
            title="Redirect Chain",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold"
        )
        redirect_table.add_column("#", justify="right", width=3)
        redirect_table.add_column("Status", justify="center", width=6)
        redirect_table.add_column("URL", width=70)
        
        for i, hop in enumerate(report.redirect_chain, 1):
            scheme_color = "green" if hop.scheme == "https" else "yellow"
            url_display = f"[{scheme_color}]{hop.url}[/{scheme_color}]"
            redirect_table.add_row(str(i), str(hop.status_code), url_display)
        
        console.print(redirect_table)
        console.print()