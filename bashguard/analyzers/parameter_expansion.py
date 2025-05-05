"""
Analyzer for variable expansion vulnerabilities.
"""

from pathlib import Path
from typing import List, Tuple

from bashguard.core import BaseAnalyzer, Vulnerability, VulnerabilityType, SeverityLevel, Description, TSParser
from bashguard.core.types import UsedVariable

class ParameterExpansionAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects issues with parameter expansion in shell scripts.
    
    It looks for potential vulnerabilities related to:
    - Expanding 0-th parameter
    """
    
    def __init__(self, script_path: Path, content: str, parser: TSParser, verbose: bool = False):
        """
        Initialize the parameter expansion analyzer.
        
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

        parameters = self.parser.get_used_variables()

        vulnerabilities = []
        
        ok, line, column = self.__0th_parameter_expansion(parameters)
        if ok:
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.PARAMETER_EXPANSION,
                severity=SeverityLevel.MEDIUM,
                description=Description.PARAMETER_EXPANSION_0,

                file_path=self.script_path,
                line_number=line, # tree_sitter starts indexing from 0
                column=column, # tree_sitter starts indexing from 0
                line_content=None,
            )
            vulnerabilities.append(vulnerability)    
        
        return vulnerabilities 
    
    def __0th_parameter_expansion(self, parameters: List[UsedVariable]) -> Tuple[bool, int, int]:
        for parameter in parameters:
            if parameter.name == '$0':
                return True, parameter.line, parameter.column
        
        return False, -1, -1