#!/usr/bin/env python3
"""
Main entry point for BashGuard
"""

import click
from pathlib import Path

from bashguard.analyzers import ScriptAnalyzer
from bashguard import __version__


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
    
    click.echo(f"Analyzing {script_path}...")

    analyzer = ScriptAnalyzer(script_path, verbose=1)
    vulnerabilities = analyzer.analyze()

    # print vulnerabilities

if __name__ == "__main__":
    cli()
