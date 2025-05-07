"""
Analyzer for variable expansion vulnerabilities.
"""
from pathlib import Path
from typing import List
from bashguard.core.vulnerability import Recommendation
from bashguard.core import BaseAnalyzer, TSParser, Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.types import UsedVariable

class VariableExpansionAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects issues with variable expansion in shell scripts.
    
    It looks for potential vulnerabilities related to:
    - Unquoted variable expansions
    - Word splitting issues
    - Globbing problems with expanded variables
    - Missing default values for parameter expansions
    """
    
    def __init__(self, script_path: Path, content: str, parser: TSParser, verbose: bool = False):
        """
        Initialize the variable expansion analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
            verbose: Whether to enable verbose logging
        """
        super().__init__(script_path, content, parser, verbose)
    
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for variable expansion vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        used_vars = self.parser.get_used_variables()

        for var in used_vars:
            # Check for unquoted variables
            vulnerabilities.extend(self._check_unquoted_variables(var))
        
        return vulnerabilities

    def _check_unquoted_variables(self, var: 'UsedVariable') -> List[Vulnerability]:
        vulnerabilities = []
        
        if not self._is_properly_quoted(var):
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.VARIABLE_EXPANSION,
                severity=SeverityLevel.HIGH,
                description=Description.VARIABLE_EXPANSION,
                file_path=self.script_path,
                line_number=var.line,
                column=var.column,
                line_content=self.lines[var.line] if var.line < len(self.lines) else None,
                recommendation=Recommendation.VARIABLE_EXPANSION
            )
            vulnerabilities.append(vulnerability)
        return vulnerabilities

    # for possible future use
    def _is_properly_single_quoted(self, var: 'UsedVariable') -> bool:
        return self.__is_properly_quoted(var, "'")

    # for possible future use
    def _is_properly_double_quoted(self, var: 'UsedVariable') -> bool:
        return self.__is_properly_quoted(var, '"')
    
    def _is_properly_quoted(self, var: 'UsedVariable') -> bool:
        return self._is_properly_double_quoted(var) or self._is_properly_single_quoted(var)
    
    def __is_properly_quoted(self, var: 'UsedVariable', quote: str) -> bool:
        """Check if a variable is properly quoted in its usage."""
        line = self.lines[var.line]
        var_name = var.name
        
        # Find the variable in the line
        start = var.column
        end = start + len(var_name)
        
        before = line[:start].rstrip()
        after = line[end:].lstrip()
        
        # Check for proper quoting
        if before.endswith(quote) and after.startswith(quote):
            return True
        
        return False