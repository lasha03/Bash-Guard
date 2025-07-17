#!/usr/bin/env python3
"""
Main entry point for BashGuard
"""

import click
import sys
from pathlib import Path

from bashguard.analyzers import ScriptAnalyzer
from bashguard import __version__
from bashguard.core.reporter import Reporter


@click.group()
@click.version_option(version=__version__, package_name="BashGuard", prog_name="BashGuard")
def cli():
    """BashGuard: A static analysis tool for Bash scripts."""
    pass


@cli.command()
@click.argument("script_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file for the report")
@click.option("--format", "-f", type=click.Choice(["text", "json", "html"]), default="text", help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def analyze(script_path, output, format, verbose):
    """Analyze a Bash script for security vulnerabilities."""
    script_path = Path(script_path)

    if not script_path.is_file():
        click.echo(f"Error: {script_path} is not a file", err=True)
        sys.exit(1)
    
    click.echo(f"Analyzing {script_path}...")

    analyzer = ScriptAnalyzer(script_path, verbose=1)
    vulnerabilities = analyzer.analyze()

    reporter = Reporter(format=format)
    report = reporter.generate_report(vulnerabilities)
    
    if output:
        output_path = Path(output)
        with open(output_path, "w") as f:
            f.write(report)
        click.echo(f"Report saved to {output_path}")
    else:
        click.echo(report)

if __name__ == "__main__":
    cli()
