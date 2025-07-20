"""
Core analyzer module that orchestrates the analysis process.
"""

from pathlib import Path
from typing import List

from bashguard.analyzers import VariableExpansionAnalyzer, ParameterExpansionAnalyzer, CommandInjectionAnalyzer, EnvironmentAnalyzer
from bashguard.analyzers.shellcheck_analyzer import ShellcheckAnalyzer
from bashguard.core import Vulnerability, BaseAnalyzer, TSParser, VulnerabilityType
from bashguard.core.logger import Logger

class ScriptAnalyzer:
    """
    Main analyzer class that coordinates the analysis process.
    """
    
    def __init__(self, script_path: Path):
        """
        Initialize the script analyzer.
        
        Args:
            script_path: Path to the script to analyze
        """
        self.script_path = script_path
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
            ShellcheckAnalyzer(self.script_path, self.content),
            EnvironmentAnalyzer(self.script_path, self.content, parser),
            ParameterExpansionAnalyzer(self.script_path, self.content, parser),
            VariableExpansionAnalyzer(self.script_path, self.content, parser),
            CommandInjectionAnalyzer(self.script_path, self.content, parser)
        ]
    
    def analyze(self) -> List[Vulnerability]:
        """
        Run all analyzers and collect the results.
        
        Returns:
            List of vulnerabilities found
        """
        all_vulnerabilities = []

        for analyzer in self.analyzers:
            Logger.v(f"Running {analyzer.__class__.__name__}...")
                
            vulnerabilities = analyzer.analyze()

            if any(vuln.vulnerability_type == VulnerabilityType.SYNTAX_ERROR for vuln in vulnerabilities):
                print("Shellcheck found some errors. Fix them before detecting security vulnerabilities.")
                break

            Logger.v(f"Found {len(vulnerabilities)} vulnerabilities.")
            
            all_vulnerabilities.extend(vulnerabilities)
        
        # Remove duplicate vulnerabilities and apply priority rules
        all_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
        
        return all_vulnerabilities
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Remove duplicate vulnerabilities and apply priority rules.
        
        Priority rules:
        1. Command injection takes priority over variable expansion for the SAME variable
        2. Remove exact duplicates based on type, line, and content
        """
        # Group vulnerabilities by line number
        line_groups = {}
        for vuln in vulnerabilities:
            line_num = vuln.line_number
            if line_num not in line_groups:
                line_groups[line_num] = []
            line_groups[line_num].append(vuln)
        
        deduplicated = []
        
        for line_num, line_vulns in line_groups.items():
            # Extract variable names from command injection vulnerabilities on this line
            cmd_injection_vars = set()
            for vuln in line_vulns:
                if vuln.vulnerability_type == VulnerabilityType.COMMAND_INJECTION:
                    # Try to extract variable name from the line content
                    line_content = vuln.line_content or ""
                    # Look for patterns like eval "$var", sh -c "$var", etc.
                    import re
                    var_matches = re.findall(r'\$(\w+)', line_content)
                    cmd_injection_vars.update(var_matches)
            
            # Filter out variable expansion vulnerabilities only if they involve the same variables as command injection
            filtered_vulns = []
            for vuln in line_vulns:
                if vuln.vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION and cmd_injection_vars:
                    # Extract variable name from variable expansion
                    line_content = vuln.line_content or ""
                    var_matches = re.findall(r'\$(\w+)', line_content)
                    # Only remove if this variable expansion involves a variable that also has command injection
                    if any(var in cmd_injection_vars for var in var_matches):
                        continue  # Skip this variable expansion as it's covered by command injection
                
                filtered_vulns.append(vuln)
            
            # Remove exact duplicates within this line
            seen = set()
            for vuln in filtered_vulns:
                # For variable expansion vulnerabilities, use a more flexible key that ignores small column differences
                if vuln.vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION:
                    line_content = vuln.line_content.strip() if vuln.line_content else ""
                    key = (vuln.vulnerability_type, vuln.line_number, line_content)
                else:
                    # For other vulnerability types, use the original detailed key
                    key = (vuln.vulnerability_type, vuln.line_number, vuln.column, vuln.line_content)
                
                if key not in seen:
                    seen.add(key)
                    deduplicated.append(vuln)
        
        return deduplicated 