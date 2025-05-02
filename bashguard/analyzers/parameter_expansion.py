"""
Analyzer for variable expansion vulnerabilities.
"""
import bashlex # type: ignore

from pathlib import Path
from typing import List

from bashguard.core.base_analyzer import BaseAnalyzer
from bashguard.core.vulnerability import Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.parser import Parser


class ParameterExpansionAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects issues with parameter expansion in shell scripts.
    
    It looks for potential vulnerabilities related to:
    - Expanding 0-th parameter
    """
    
    def __init__(self, script_path: Path, content: str, verbose: bool = False):
        """
        Initialize the parameter expansion analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
            verbose: Whether to enable verbose logging
        """
        super().__init__(script_path, content, verbose)
    
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for variable expansion vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """

        parser = Parser(self.content)
        parser.parse()
        parameters = parser.get_parameters()

        vulnerabilities = []
        
        if self.__0th_parameter_expansion(parameters):
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.PARAMETER_EXPANSION,
                severity=SeverityLevel.MEDIUM,
                description=Description.PARAMETER_EXPANSION_0,

                file_path=self.script_path,
                line_number=-1,
                column=None,
                line_content=None,
            )
            vulnerabilities.append(vulnerability)    
        
        return vulnerabilities 
    
    def __0th_parameter_expansion(self, parameters: List[bashlex.ast.node]) -> bool:
        for parameter in parameters:
            if parameter.value == '0':
                return True