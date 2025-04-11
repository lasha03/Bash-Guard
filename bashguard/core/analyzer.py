"""
Core analyzer module that orchestrates the analysis process.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Type

from bashguard.core.vulnerability import Vulnerability
from bashguard.core.base_analyzer import BaseAnalyzer

class ScriptAnalyzer:
    """
    Main analyzer class that coordinates the analysis process.
    Uses the Strategy pattern to allow for easy addition or removal of analyzers.
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
        self.analyzers = self._get_analyzers()
        
    def _read_script(self) -> str:
        """Read the script content."""
        with open(self.script_path, 'r') as f:
            return f.read()
    
    def _get_analyzers(self) -> List[BaseAnalyzer]:
        """Get all analyzers to be used for the analysis."""
        analyzers = []
        return analyzers
    
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
        
        return all_vulnerabilities 