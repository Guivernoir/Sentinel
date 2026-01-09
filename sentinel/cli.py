"""
Command-line interface. Mission control.
Where user intent meets tactical execution.
"""

import asyncio
import sys
from typing import Optional

import typer
from rich.console import Console

from sentinel.analyzer import SecurityHeadersAnalyzer
from sentinel.renderer import render_report
from sentinel.exceptions import (
    SentinelException,
    AnalysisTimeout,
    ConnectionFailed,
)

console = Console()

app = typer.Typer(
    help="Analyze HTTP security headers with precision.",
    add_completion=False
)


@app.command()
def analyze(
    url: str = typer.Argument(..., help="Target URL to analyze"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed analysis"),
    timeout: int = typer.Option(10, "--timeout", "-t", help="Request timeout in seconds"),
    no_redirect: bool = typer.Option(False, "--no-redirect", help="Do not follow redirects"),
    max_redirects: int = typer.Option(10, "--max-redirects", help="Maximum redirect hops")
) -> None:
    """
    Analyze HTTP security headers for the specified URL.
    
    Deploy tactical analysis to assess security posture.
    
    Examples:
    
        sentinel analyze example.com
        
        sentinel analyze https://example.com --verbose
        
        sentinel analyze example.com -t 30 --no-redirect
    """
    console.print("\n[cyan]Initiating security header analysis...[/cyan]\n")
    
    analyzer = SecurityHeadersAnalyzer(
        timeout=timeout,
        follow_redirects=not no_redirect,
        max_redirects=max_redirects
    )
    
    # Execute the mission - with proper exception handling
    try:
        report = asyncio.run(analyzer.analyze(url))
        render_report(report, verbose=verbose)
        sys.exit(0)
    
    except AnalysisTimeout as e:
        console.print(f"\n[red]âœ— Timeout:[/red] {e}\n", style="bold")
        console.print(f"[dim]The target did not respond within {timeout} seconds.[/dim]")
        console.print("[dim]Try increasing timeout with --timeout flag.[/dim]\n")
        sys.exit(1)
    
    except ConnectionFailed as e:
        console.print(f"\n[red]âœ— Connection Failed:[/red] {e}\n", style="bold")
        console.print("[dim]Unable to establish connection to target.[/dim]")
        console.print("[dim]Check URL and network connectivity.[/dim]\n")
        sys.exit(1)
    
    except SentinelException as e:
        console.print(f"\n[red]âœ— Analysis Failed:[/red] {e}\n", style="bold")
        console.print("[dim]An unexpected error occurred during analysis.[/dim]")
        if verbose:
            console.print_exception()
        sys.exit(1)
    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Analysis interrupted by user.[/yellow]\n")
        sys.exit(130)  # Standard exit code for SIGINT
    
    except Exception as e:
        console.print(f"\n[red]âœ— Critical Error:[/red] {e}\n", style="bold")
        console.print("[dim]An unexpected error occurred.[/dim]")
        if verbose:
            console.print_exception()
        sys.exit(1)


@app.command()
def version() -> None:
    """Display version information."""
    from sentinel import __version__, __author__
    
    console.print(f"\n[bold cyan]Sentinel Security Header Analyzer[/bold cyan]")
    console.print(f"[dim]Version {__version__}[/dim]")
    console.print(f"[dim]Author: {__author__}[/dim]")
    console.print("[dim]Tactical security analysis for modern web applications[/dim]\n")


@app.callback()
def main(
    ctx: typer.Context,
    debug: Optional[bool] = typer.Option(
        None,
        "--debug",
        help="Enable debug logging",
        hidden=True
    )
) -> None:
    """
    Sentinel Security Header Analyzer
    
    Well, that was quite the strategic decision to run this, wasn't it?
    """
    if debug:
        import logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )


if __name__ == "__main__":
    app()