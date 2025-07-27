#!/usr/bin/env python3
"""
Main entry point for BashGuard
"""
import click
import sys
from pathlib import Path
from bashguard.core.logger import Logger
from bashguard.analyzers import ScriptAnalyzer
from bashguard import __version__
from bashguard.core.reporter import Reporter
from bashguard.fixers.fixer import Fixer

@click.command()
@click.argument("script_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", type=click.Path(), help="Output file for the report")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--fix", is_flag=True, help="Automatically fix issues in the script")
@click.option("--fix-output", type=click.Path(), help="Output file for the fixed script. If not specified, the script will be overwritten.")
@click.version_option(version=__version__, package_name="BashGuard", prog_name="BashGuard")
def cli(script_path, output, format, verbose, fix, fix_output):
    """BashGuard: A static analysis tool for Bash scripts.
    
    Analyze a Bash script for security vulnerabilities.
    """
    script_path = Path(script_path)
    if not script_path.is_file():
        click.echo(f"Error: {script_path} is not a file", err=True)
        sys.exit(1)
    
    # Initialize global logger
    # verbosity can be specified by the user, debug flag is for internal use only.
    Logger.init(verbose, True)
    
    analyzer = ScriptAnalyzer(script_path)
    vulnerabilities = analyzer.analyze()
    
    reporter = Reporter(file_path=script_path, format=format)
    report = reporter.generate_report(vulnerabilities)
    
    if output:
        output_path = Path(output)
        with open(output_path, "w") as f:
            f.write(report)
        click.echo(f"Report saved to {output_path}")
    else:
        click.echo(report)
    
    if fix:
        click.echo(f"Starting to fix vulnerabilities")
        click.echo("="*40 + "\n")
        fixer = Fixer(script_path, output_path=fix_output)
        fixer.fix(vulnerabilities)
        click.echo(f"Code has been fixed")

if __name__ == "__main__":
    cli()