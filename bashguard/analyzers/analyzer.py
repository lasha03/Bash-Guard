"""
Core analyzer module that orchestrates the analysis process.
"""

from pathlib import Path
from typing import List

from bashguard.analyzers import VariableExpansionAnalyzer, ParameterExpansionAnalyzer, CommandInjectionAnalyzer, EnvironmentAnalyzer
from bashguard.analyzers.shellcheck_analyzer import ShellcheckAnalyzer
from bashguard.core import Vulnerability, BaseAnalyzer, TSParser

class ScriptAnalyzer:
    """
    Main analyzer class that coordinates the analysis process.
    """
    
    def __init__(self, script_path: Path, verbose: bool = False):
        """
        Initialize the script analyzer.
        
        Args:
            script_path: Path to the script to analyze
            verbose: Whether to enable verbose logging
        """
        self.script_path = script_path
        self.verbose = verbose
        self.content = self._read_script()

        parser = TSParser(bytes(self.content, 'utf-8'))
        self._init_analyzers(parser)
        
    def _read_script(self) -> str:
        """Read the script content."""
        with open(self.script_path, 'r') as f:
            return f.read()
    
    def _init_analyzers(self, parser: TSParser):
        """Get all analyzers to be used for the analysis."""
        self.analyzers: list[BaseAnalyzer] = [
            ShellcheckAnalyzer(self.script_path, self.content, self.verbose),
            EnvironmentAnalyzer(self.script_path, self.content, parser, self.verbose),
            ParameterExpansionAnalyzer(self.script_path, self.content, parser, self.verbose),
            VariableExpansionAnalyzer(self.script_path, self.content, parser, self.verbose),
            CommandInjectionAnalyzer(self.script_path, self.content, parser, self.verbose)
        ]
    
    def analyze(self) -> List[Vulnerability]:
        """
        Run all analyzers and collect the results.
        
        Returns:
            List of vulnerabilities found
        """
        all_vulnerabilities = []
        
        for analyzer in self.analyzers:
            if self.verbose:
                print(f"Running {analyzer.__class__.__name__}...")
            
            vulnerabilities = analyzer.analyze()
            all_vulnerabilities.extend(vulnerabilities)
            
            if self.verbose:
                print(f"Found {len(vulnerabilities)} vulnerabilities.")
            

            if isinstance(analyzer, ShellcheckAnalyzer) and len(vulnerabilities) > 0:
                if self.verbose:
                    print("Shellcheck found some errors. Fix them before detecting security vulnerabilities.")
                
                break
        
        return all_vulnerabilities 